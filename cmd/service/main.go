package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"path"
	"strings"
	"text/template"

	"github.com/iancoleman/strcase"
)

func main() {
	log.SetFlags(0)

	var in, out, pkg string
	flag.StringVar(&in, "in", "schema/Opc.Ua.Types.bsd", "Path to Opc.Ua.Types.bsd file")
	flag.StringVar(&out, "out", "ua", "Path to output directory")
	flag.StringVar(&pkg, "pkg", "ua", "Go package name")
	flag.Parse()

	dict, err := ReadTypes(in)
	if err != nil {
		log.Fatalf("Failed to read type definitions: %s", err)
	}

	write(pkg, Enums(dict), path.Join(out, "enums_gen.go"))
	for _, t := range ExtObjects(dict) {
		filename := strcase.ToKebab(t.Name) + "_gen.go"
		write(pkg, []Type{t}, path.Join(out, filename))
	}
}

func write(pkg string, types []Type, filename string) {
	var b bytes.Buffer
	if err := tmplHeader.Execute(&b, pkg); err != nil {
		log.Fatalf("Failed to generate header: %s", err)
	}

	for _, t := range types {
		if err := FormatType(&b, t); err != nil {
			log.Fatalf("Failed to generate code for %s: %v", t.Name, err)
		}
	}

	if err := ioutil.WriteFile(filename, b.Bytes(), 0644); err != nil {
		log.Fatalf("Failed to write %s: %v", filename, err)
	}

	if err := exec.Command("goimports", "-w", filename).Run(); err != nil {
		log.Fatalf("Failed to format %s: %v", filename, err)
	}
	log.Printf("Wrote %s", filename)
}

var tmplHeader = template.Must(template.New("").Parse(`
// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Code generated by cmd/service. DO NOT EDIT!

package {{.}}

import "time"

`))

func Enums(dict *TypeDictionary) []Type {
	var enums []Type
	for _, t := range dict.Enums {
		e := Type{
			Name: goName(t.Name),
			Kind: KindEnum,
		}

		switch {
		case t.Bits <= 8:
			e.Type = "uint8"
		case t.Bits <= 16:
			e.Type = "uint16"
		case t.Bits <= 32:
			e.Type = "uint32"
		default:
			e.Type = "uint64"
		}

		for _, val := range t.Values {
			v := Value{
				Name:  goName(e.Name + val.Name),
				Value: val.Value,
			}
			e.Values = append(e.Values, v)
		}
		enums = append(enums, e)
	}
	return enums
}

func ExtObjects(dict *TypeDictionary) []Type {
	baseTypes := map[string]*Type{
		// Extensionobject is the base class for all extension objects.
		"ua:ExtensionObject": &Type{Name: "ExtensionObject"},

		// DataTypeDefinition is referenced in Opc.Ua.Types.bsd but not defined there
		// From what I can tell it is an abstract base class without any fields.
		// We define it here to be able to generate code for derived classes.
		"tns:DataTypeDefinition": &Type{Name: "DataTypeDefinition"},
	}

	var objects []Type
	for _, t := range dict.Types {
		// check if the base type is derived from ExtensionObject
		baseType := baseTypes[t.BaseType]
		if baseType == nil {
			continue
		}

		o := Type{
			Name: goName(t.Name),
			Kind: KindExtensionObject,
			Base: baseType,
		}

		for _, f := range t.Fields {
			// skip fields containing the length of an array since
			// we create an array type
			if t.IsLengthField(f) {
				continue
			}

			of := Field{
				Name: goName(f.Name),
				Type: goFieldType(f),
			}
			o.Fields = append(o.Fields, of)
		}

		// register it as derived from ExtensionObject
		// we need to register it with target namespace 'tns:' since t.Name only contains the
		// base name.
		baseTypes["tns:"+t.Name] = &o
		log.Printf("register tns.%s", t.Name)

		objects = append(objects, o)
	}
	return objects
}

type Kind int

const (
	KindInvalid Kind = iota
	KindEnum
	KindExtensionObject
)

type Type struct {
	// Name is the Go name of the OPC/UA type.
	Name string

	// Type is the Go type of the OPC/UA type.
	Type string

	// Kind is the kind of OPC/UA type.
	Kind Kind

	// Base is the OPC/UA type this type is derived from.
	Base *Type

	// Fields is the list of struct fields.
	Fields []Field

	// Values is the list of enum values.
	Values []Value
}

type Value struct {
	Name  string
	Value int
}

type Field struct {
	Name string
	Type string
}

func FormatType(w io.Writer, t Type) error {
	switch t.Kind {
	case KindEnum:
		return tmplEnum.Execute(w, t)
	case KindExtensionObject:
		return tmplExtObject.Execute(w, t)
	default:
		return fmt.Errorf("invalid type: %d", t.Kind)
	}
}

var tmplEnum = template.Must(template.New("").Parse(`
type {{.Name}} {{.Type}}

const (
	{{$Name := .Name}}
	{{range $i, $v := .Values}}{{$v.Name}} {{$Name}} = {{$v.Value}}
	{{end}}
)
`))

var tmplExtObject = template.Must(template.New("").Parse(`
{{if .Fields}}
type {{.Name}} struct {
	{{range $i, $v := .Fields}}{{$v.Name}} {{$v.Type}}
	{{end}}
}
{{end}}
`))

var builtins = map[string]string{
	"opc:Boolean":    "bool",
	"opc:Byte":       "uint8",
	"opc:SByte":      "int8",
	"opc:Int16":      "int16",
	"opc:Int32":      "int32",
	"opc:Int64":      "int64",
	"opc:UInt16":     "uint16",
	"opc:UInt32":     "uint32",
	"opc:UInt64":     "uint64",
	"opc:Float":      "float32",
	"opc:Double":     "float64",
	"opc:String":     "string",
	"opc:DateTime":   "time.Time",
	"opc:ByteString": "[]byte",
	"ua:StatusCode":  "StatusCode",
	"opc:Guid":       "*GUID",
}

func goFieldType(f *StructField) string {
	t, builtin := builtins[f.Type]
	if t == "" {
		prefix := strings.NewReplacer("ua:", "", "tns:", "")
		t = goName(prefix.Replace(f.Type))
	}
	if !f.IsEnum && !builtin {
		t = "*" + t
	}
	if f.IsSlice() {
		t = "[]" + t
	}
	return t
}

func goName(s string) string {
	r1 := strings.NewReplacer(
		"Guid", "GUID",
		"Id", "ID",
		"Json", "JSON",
		"QualityOfService", "QoS",
		"Uadp", "UADP",
		"Uri", "URI",
		"Url", "URL",
	)
	r2 := strings.NewReplacer(
		"IDentity", "Identity",
	)
	return r2.Replace(r1.Replace(s))
}
