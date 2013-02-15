! File: pcap.factor
! Version: 0.1
! DRI: Dave Carlton
! Description: Vocabulary to read pcap files created by tcpdump.
! Copyright (C) 2013 Dave Carlton.
! See http://factorcode.org/license.txt for BSD license.

USING: accessors alien.accessors alien.c-types alien.endian
alien.syntax classes.struct io io.encodings.binary io.files kernel
namespaces struct variables ;

IN: pcap

TYPEDEF: uint in_addr_t

BE-PACKED-STRUCT: be-in_addr
{ s_addr uint }
;

BE-PACKED-STRUCT: be-header
{ src uchar[6] }
{ dst uchar[6] }
{ type ushort }
;

BE-PACKED-STRUCT: be-ip
{ src uchar[6] }
{ dst uchar[6] }
{ type ushort }
{ ip_v uint bits: 4 }
{ ip_hl uint bits: 4 }
{ ip_tos uchar }
{ ip_len ushort }
{ ip_id ushort }
{ ip_ttl uchar }
{ ip_p uchar }
{ ip_char ushort }
{ ip_src uint }
{ ip_dst uint }
;

BE-PACKED-STRUCT: be-pcap-header
{ pcap_magic uint }
{ pcap_vmajor ushort }
{ pcap_vminor ushort }
{ pcap_zoff uint }
{ pcap_tsa uint }
{ pcap_snaplen uint }
{ pcap_headtype uint }
;

LE-PACKED-STRUCT: le-in_addr
{ s_addr uint }
;

LE-PACKED-STRUCT: le-header
{ src uchar[6] }
{ dst uchar[6] }
{ type ushort }
;

LE-PACKED-STRUCT: le-ip
{ src uchar[6] }
{ dst uchar[6] }
{ type ushort }
{ ip_v uint bits: 4 }
{ ip_hl uint bits: 4 }
{ ip_tos uchar }
{ ip_len ushort }
{ ip_id ushort }
{ ip_ttl uchar }
{ ip_p uchar }
{ ip_char ushort }
{ ip_src uint }
{ ip_dst uint }
;

LE-PACKED-STRUCT: le-pcap-header
{ pcap_magic uint }
{ pcap_vmajor ushort }
{ pcap_vminor ushort }
{ pcap_zoff uint }
{ pcap_tsa uint }
{ pcap_snaplen uint }
{ pcap_headtype uint }
;

VAR: pcap-filereader

TUPLE: pcapfile  path filereader byteorder ;

PRIVATE>
CONSTANT: be-magic 0xa1b2c3d4
CONSTANT: le-magic 0xd4c3b2a1

: be? ( B{} -- boolean )
    0 alien-unsigned-4  be-magic = ;

: read-magic ( pcapfile -- B{} )
    filereader>> [ 4 read ] with-input-stream ;

: pcap-byteorder! ( pcapfile -- )
    dup  read-magic be? >>byteorder  drop ;

: pcap-reset ( pcapfile -- )
    dup path>> binary <file-reader> >>filereader
    set: pcap-filereader ;
PRIVATE>

: <pcapfile> ( path -- )
    pcapfile new
    swap >>path  pcap-reset
    pcap-filereader pcap-byteorder! ;

: pcap-filereader@ (  -- filereader )
    pcap-filereader dup
    filereader>> disposed>>
    [ dup pcap-reset ] when
    filereader>> ;

: with-pcapfile ( quot -- )
    pcap-filereader@ swap with-input-stream ; inline

: pcap-header ( -- struct )
    pcap-filereader byteorder>>
    [ le-pcap-header ] [ be-pcap-header ] if ;

: pcap-header@ ( -- <pcap-header> )
    [ pcap-header sizeof read ] with-pcapfile
    pcap-header memory>struct ;

"~/Desktop/9997.dmp" <pcapfile>