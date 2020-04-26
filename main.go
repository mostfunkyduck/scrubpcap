// How to set a filter and only read certain packets from the pcap file

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	inputFile  = flag.String("inputfile", "", "path to pcap file to trim")
	outputFile = flag.String("outputfile", "", "path to pcap file to output trimmed data to")
	// TODO use a better logging library to implement this, fsck the default one
	verbose = flag.Bool("verbose", false, "verbose logging, unimplemented")
	handle  *pcap.Handle
	err     error
)

// Given a packet, pulls out all the low level layers, stripping anything
// above the transport layer
// Arguments
//   packet: the packet to filter
func filterLayers(packet gopacket.Packet) ([]gopacket.SerializableLayer, error) {
	// want to call serialize layers so that we don't try to serialize truncated data
	// This should serialize a new packet with ONLY the ethernet, ipv4, and tcp layers of
	// the original.  the casting takes the old packet's layers and makes them readable
	newlayers := []gopacket.SerializableLayer{}
	for _, l := range packet.Layers() {
		log.Printf("saw layer: [%s]\n", l.LayerType())
		if l.LayerType() == layers.LayerTypeLinuxSLL {
			// unless gopacket accepts my serialize function, we need to hack up SLL captures like this
			// NOTE: there may be other layers that need this treatment, remains to be seen
			newLayer := &SerializableLinuxSLL{*l.(*layers.LinuxSLL)}
			l = newLayer
		}

		newlayer, ok := l.(gopacket.SerializableLayer)
		if ok {
			newlayers = append(newlayers, newlayer)
		} else {
			return newlayers, fmt.Errorf("error, could not serialize [%v]\n", l)
		}

		// TODO keep a list of end state layers
		if l.LayerType() == layers.LayerTypeTCP || l.LayerType() == layers.LayerTypeUDP {
			// this is the highest up the stack we're going to go, further than this is payload territory
			log.Printf("trimming packet after [%s] layer seen\n", l.LayerType())
			break
		}
	}
	return newlayers, nil
}

// Given a packet, returns a version with potentially sensitive payloads trimmed
// Arguments
//   packet: the packet to trim
func trimPacket(packet gopacket.Packet) (gopacket.Packet, error) {
	log.Printf("trimming packet [%s]\n", packet)
	trimmedLayers, err := filterLayers(packet)
	if err != nil {
		return nil, err
	}

	// we don't want to change anything we don't have to, pls
	options := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       false,
	}

	// make a new packet with the trimmed contents of the old packet
	newBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(newBuffer, options, trimmedLayers...)
	if err != nil {
		return nil, err
	}

	// using nocopy may be a premature optimization, I need to see how
	// much of a difference it makes at some point.
	// Creating this new packet will make the data go through decodeding in gopacket
	// which will handle truncation as expected
	newpacket := gopacket.NewPacket(newBuffer.Bytes(), trimmedLayers[0].LayerType(), gopacket.NoCopy)
	return newpacket, nil
}

// Outputs the timmed packet to a pcapgo writer
// Arguments:
//    packet: the trimmed packet
//		originalLength: the length of the untrimmed packet, which must be preserved in the final result
//										to pass sanity checks
//		writer: an open pcapgo writer for outputting the trimmed packet
func writeTrimmedPacket(packet gopacket.Packet, originalLength int, writer *pcapgo.Writer) error {
	// we'll need to make sure that the capture info represents the correct size, it defaults to being 0'd out
	// for new packets
	ci := packet.Metadata().CaptureInfo
	ci.CaptureLength = len(packet.Data())
	ci.Length = originalLength
	err = writer.WritePacket(ci, packet.Data())
	if err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()
	// yuuuup this is basically how I have to do it until I use a better flag library
	if len(os.Args) <= 1 {
		flag.PrintDefaults()
		return
	}

	if *inputFile == "" {
		log.Fatal("inputfile is a required argument")
	}

	if *outputFile == "" {
		log.Fatal("outputfile is a required argument")
	}
	// TODO configurable logging, flags for input and output files, flags for skipping errors
	// open input and output files
	handle, err = pcap.OpenOffline(*inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	f, _ := os.Create(*outputFile)
	defer f.Close()
	w := pcapgo.NewWriter(f)

	// size == max payload size on a capture, we're not filtering here, so it
	// shouldn't really matter, but just in case, i'm setting it to the max
	// details on the header at http://wiki.wireshark.org/Development/LibpcapFileFormat

	// Also, this method of getting the equivalent of C's nice, handy MAX_INT-esque macros
	// is the only valid way according to stackoverflow https://stackoverflow.com/questions/6878590/the-maximum-value-for-an-int-type-in-go
	// TODO make this use the type found in the pcap file
	w.WriteFileHeader(^uint32(0), layers.LinkTypeLinuxSLL)

	for packet := range packetSource.Packets() {
		trimmedPacket, err := trimPacket(packet)
		// TODO allow skipping errors
		if err != nil {
			panic(err)
		}

		// TODO output broken packets to a different file when we skip errors
		err = writeTrimmedPacket(trimmedPacket, packet.Metadata().CaptureInfo.Length, w)
		if err != nil {
			panic(err)
		}
	}
}
