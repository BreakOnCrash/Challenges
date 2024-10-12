/*
build:

	CGO_ENABLED=1 go build -ldflags "-s -w" -trimpath -o fsyscall main.go

usage:

	$ fsyscall -t tests/macho/ptrace-syscall-demo

	File: tests/macho/ptrace-syscall-demo
	Section: __TEXT.__text
	0x100003efc:  03 00 80 d2       mov     x3, #0
	0x100003f00:  02 00 80 d2       mov     x2, #0
	0x100003f04:  01 00 80 d2       mov     x1, #0
	0x100003f08:  e0 03 80 d2       mov     x0, #0x1f
	0x100003f0c:  50 03 80 d2       mov     x16, #0x1a
	0x100003f10:  01 10 00 d4       svc     #0x80
*/

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"sync"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func main() {
	var target = flag.String("t", "", "File to be analyzed")
	flag.Parse()

	if *target == "" {
		flag.Usage()
		return
	}

	if err := FuzzMachoSyscall(*target); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

var ErrOnlySupportAarch64 = errors.New("only support aarch64")

func FuzzMachoSyscall(file string) error {
	var m *macho.File

	obj, err := macho.OpenFat(file)
	if err != nil {
		if err != macho.ErrNotFat {
			return err
		}

		m, err = macho.Open(file)
		if err != nil {
			return err
		}
		defer m.Close()
		if m.CPU != types.CPUArm64 {
			return ErrOnlySupportAarch64
		}
	} else {
		defer obj.Close()

		for _, arch := range obj.Arches {
			if arch.CPU == types.CPUArm64 {
				m = arch.File
			}
		}
	}

	if m == nil {
		return ErrOnlySupportAarch64
	}

	for _, section := range m.Sections {
		if section.Seg != "__TEXT" {
			continue
		}
		if section.Name != "__text" {
			continue
		}

		data, err := section.Data()
		if err != nil {
			return err
		}

		fmt.Printf("File: %s \nSection: %s.%s\n", file, section.Seg, section.Name)
		if err := searchASM(section.Addr, bytes.NewReader(data)); err != nil {
			return err
		}
	}

	return nil
}

const (
	aarch64Syscall = "svc\t#0x80"
)

var asmStack = newStack(8)

func searchASM(baseAddr uint64, r io.Reader) error {
	var err error
	var startAddr uint64
	var instrValue uint32
	var results [1024]byte
	var instrLen = uint64(binary.Size(uint32(0)))

	defer asmStack.clean()

	for {
		err = binary.Read(r, binary.LittleEndian, &instrValue)
		if err == io.EOF {
			break
		}

		instruction, err := disassemble.Disassemble(startAddr, instrValue, &results)
		if err != nil {
			// TODO 忽略反编译错误
			fmt.Printf("disassemble: %x, error: %s\n", instrValue, err)
			startAddr += instrLen
			continue
		}

		cur := instrData{
			addr:        uint64(baseAddr + startAddr),
			opcode:      instrValue,
			instruction: instruction,
		}

		if instruction == aarch64Syscall {
			contexts := asmStack.dumpAndClean()
			for _, c := range contexts {
				fmt.Printf("%#08x:  %s\t%s\n",
					c.addr,
					disassemble.GetOpCodeByteString(c.opcode),
					c.instruction)
			}
			fmt.Printf("%#08x:  %s\t%s\n\n",
				cur.addr,
				disassemble.GetOpCodeByteString(cur.opcode),
				cur.instruction)
		} else {
			asmStack.push(cur)
		}

		startAddr += instrLen
	}

	return nil
}

type instrData struct {
	addr        uint64
	opcode      uint32
	instruction string
}

type stack struct {
	mux      sync.Mutex
	max      uint8
	elements []instrData
}

func newStack(max uint8) *stack {
	return &stack{
		max:      max,
		elements: make([]instrData, 0, max),
	}
}

func (s *stack) push(e instrData) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if len(s.elements) >= int(s.max) {
		s.elements = s.elements[1:]
	}
	s.elements = append(s.elements, e)
}

func (s *stack) clean() {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.elements = s.elements[:0]
}

func (s *stack) dumpAndClean() []instrData {
	s.mux.Lock()
	defer s.mux.Unlock()

	dumped := s.elements
	s.elements = s.elements[:0]
	return dumped
}
