package main

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SerializableLinuxSLL struct {
	layers.LinuxSLL
}

func (sll *SerializableLinuxSLL) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(16)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, 0)
	binary.BigEndian.PutUint16(bytes[0:2], uint16(sll.PacketType))
	binary.BigEndian.PutUint16(bytes[2:4], sll.AddrType)
	binary.BigEndian.PutUint16(bytes[4:6], sll.AddrLen)
	binary.BigEndian.PutUint16(bytes[6:sll.AddrLen+6], binary.BigEndian.Uint16(sll.Addr))
	binary.BigEndian.PutUint16(bytes[14:16], uint16(sll.EthernetType))
	return nil
}
