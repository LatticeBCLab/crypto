package rlp

import (
	"testing"
)

type A2 struct {
	Data      []byte
	A2        uint32
	ExtraData []byte
	Version   uint32
}

type A struct {
	Data      []byte
	A2        uint32
	ExtraData []byte
	A3        uint32
	Version   uint32
}

type A1 struct {
	Data []byte
}

type Aw struct {
	A2        uint32
	ExtraData []byte `rlp:"nil"`
}

type At struct {
	A3 uint32
}

type AVersionManager struct {
	Target *A
}

func (avm *AVersionManager) encode2(a *A2) ([][]byte, uint32, error) {
	data := make([][]byte, 0, a.Version)
	if a.Version >= 0 {
		d1, err := EncodeToBytes(&A1{Data: a.Data})
		if err != nil {
			return nil, 0, err
		}
		data = append(data, d1)
	}
	if a.Version >= 1 {
		d1, err := EncodeToBytes(&Aw{A2: a.A2, ExtraData: a.ExtraData})
		if err != nil {
			return nil, 0, err
		}
		data = append(data, d1)
	}
	return data, a.Version, nil
}

func (avm *AVersionManager) decode(data [][]byte, version uint32) {
	if avm.Target == nil {
		avm.Target = new(A)
	}
	count := 0
	if version >= 0 {
		a1 := new(A1)
		DecodeBytes(data[count], a1)
		count++
		avm.Target.Data = a1.Data
	}
	if version >= 1 {
		a2 := new(Aw)
		DecodeBytes(data[count], a2)
		count++
		avm.Target.A2 = a2.A2
		avm.Target.ExtraData = a2.ExtraData
	}
	if version >= 2 {
		a3 := new(At)
		DecodeBytes(data[count], a3)
		count++
		avm.Target.A3 = a3.A3
	} else {
		avm.Target.A3 = 1
	}
}

func (avm *AVersionManager) encode(a *A) ([][]byte, uint32, error) {
	data := make([][]byte, 0, a.Version)
	if a.Version >= 0 {
		d1, err := EncodeToBytes(&A1{Data: a.Data})
		if err != nil {
			return nil, 0, err
		}
		data = append(data, d1)
	}
	if a.Version >= 1 {
		d1, err := EncodeToBytes(&Aw{A2: a.A2, ExtraData: a.ExtraData})
		if err != nil {
			return nil, 0, err
		}
		data = append(data, d1)
	}
	if a.Version >= 2 {
		d1, err := EncodeToBytes(&At{A3: a.A3})
		if err != nil {
			return nil, 0, err
		}
		data = append(data, d1)
	}
	return data, a.Version, nil
}

func TestUpdate(t *testing.T) {
	a2 := &A2{Data: []byte{0x00, 0x01}, A2: 1, ExtraData: []byte{0x00, 0x02}, Version: 1}
	//a1 := &A1{Data: []byte{0x00, 0x01}}
	avm := new(AVersionManager)
	data, version, err := avm.encode2(a2)
	t.Log("data", data, "version", version, "err", err)
	avm.decode(data, version)
	t.Log("target", avm.Target)

	a3 := &A{Data: []byte{0x00, 0x01}, A2: 1, ExtraData: []byte{0x00, 0x02}, A3: 3, Version: 2}
	avm2 := new(AVersionManager)
	data, version, err = avm2.encode(a3)
	t.Log("data", data, "version", version, "err", err)
	avm.decode(data, version)
	t.Log("target", avm.Target)
}

func TestRlpNil(t *testing.T) {
	a1 := A1{Data: []byte{0x00, 0x01}}
	aw := Aw{A2: 1, ExtraData: nil}
	b1, err := EncodeToBytes(a1)
	bw, err := EncodeToBytes(aw)
	t.Log("b1", b1, "bw", bw, "err", err)
	aw2 := new(Aw)
	err = DecodeBytes(b1, aw2)
	t.Log("aw2", aw2, "err", err)
}

func TestSliceInterface(t *testing.T) {
	//这种方法不行，解析的时候会按照数组去解析，这样就会出现问题，数组内的数据会被替换，而不是依次解析
	a1 := A1{Data: []byte{0x00, 0x01}}
	aw := Aw{A2: 1, ExtraData: []byte{0x00}}
	vd := []interface{}{a1, aw}
	b1, err := EncodeToBytes(&vd)
	t.Log("b1", b1, "err", err)
	a2 := new(A1)
	aw2 := new(Aw)
	aw3 := []interface{}{a2, aw2}
	err = DecodeBytes(b1, &aw3)
	t.Log("a2", a2, "aw2", aw2, "aw3", aw3, "err", err)
}
