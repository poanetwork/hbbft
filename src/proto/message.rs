// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(PartialEq,Clone,Default)]
pub struct MessageProto {
    // message oneof groups
    payload: ::std::option::Option<MessageProto_oneof_payload>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for MessageProto {}

#[derive(Clone,PartialEq)]
pub enum MessageProto_oneof_payload {
    broadcast(BroadcastProto),
    agreement(AgreementProto),
}

impl MessageProto {
    pub fn new() -> MessageProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static MessageProto {
        static mut instance: ::protobuf::lazy::Lazy<MessageProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const MessageProto,
        };
        unsafe {
            instance.get(MessageProto::new)
        }
    }

    // .BroadcastProto broadcast = 1;

    pub fn clear_broadcast(&mut self) {
        self.payload = ::std::option::Option::None;
    }

    pub fn has_broadcast(&self) -> bool {
        match self.payload {
            ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_broadcast(&mut self, v: BroadcastProto) {
        self.payload = ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(v))
    }

    // Mutable pointer to the field.
    pub fn mut_broadcast(&mut self) -> &mut BroadcastProto {
        if let ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(_)) = self.payload {
        } else {
            self.payload = ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(BroadcastProto::new()));
        }
        match self.payload {
            ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_broadcast(&mut self) -> BroadcastProto {
        if self.has_broadcast() {
            match self.payload.take() {
                ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(v)) => v,
                _ => panic!(),
            }
        } else {
            BroadcastProto::new()
        }
    }

    pub fn get_broadcast(&self) -> &BroadcastProto {
        match self.payload {
            ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(ref v)) => v,
            _ => BroadcastProto::default_instance(),
        }
    }

    // .AgreementProto agreement = 2;

    pub fn clear_agreement(&mut self) {
        self.payload = ::std::option::Option::None;
    }

    pub fn has_agreement(&self) -> bool {
        match self.payload {
            ::std::option::Option::Some(MessageProto_oneof_payload::agreement(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_agreement(&mut self, v: AgreementProto) {
        self.payload = ::std::option::Option::Some(MessageProto_oneof_payload::agreement(v))
    }

    // Mutable pointer to the field.
    pub fn mut_agreement(&mut self) -> &mut AgreementProto {
        if let ::std::option::Option::Some(MessageProto_oneof_payload::agreement(_)) = self.payload {
        } else {
            self.payload = ::std::option::Option::Some(MessageProto_oneof_payload::agreement(AgreementProto::new()));
        }
        match self.payload {
            ::std::option::Option::Some(MessageProto_oneof_payload::agreement(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_agreement(&mut self) -> AgreementProto {
        if self.has_agreement() {
            match self.payload.take() {
                ::std::option::Option::Some(MessageProto_oneof_payload::agreement(v)) => v,
                _ => panic!(),
            }
        } else {
            AgreementProto::new()
        }
    }

    pub fn get_agreement(&self) -> &AgreementProto {
        match self.payload {
            ::std::option::Option::Some(MessageProto_oneof_payload::agreement(ref v)) => v,
            _ => AgreementProto::default_instance(),
        }
    }
}

impl ::protobuf::Message for MessageProto {
    fn is_initialized(&self) -> bool {
        if let Some(MessageProto_oneof_payload::broadcast(ref v)) = self.payload {
            if !v.is_initialized() {
                return false;
            }
        }
        if let Some(MessageProto_oneof_payload::agreement(ref v)) = self.payload {
            if !v.is_initialized() {
                return false;
            }
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    self.payload = ::std::option::Option::Some(MessageProto_oneof_payload::broadcast(is.read_message()?));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    self.payload = ::std::option::Option::Some(MessageProto_oneof_payload::agreement(is.read_message()?));
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let ::std::option::Option::Some(ref v) = self.payload {
            match v {
                &MessageProto_oneof_payload::broadcast(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &MessageProto_oneof_payload::agreement(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
            };
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let ::std::option::Option::Some(ref v) = self.payload {
            match v {
                &MessageProto_oneof_payload::broadcast(ref v) => {
                    os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
                    os.write_raw_varint32(v.get_cached_size())?;
                    v.write_to_with_cached_sizes(os)?;
                },
                &MessageProto_oneof_payload::agreement(ref v) => {
                    os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
                    os.write_raw_varint32(v.get_cached_size())?;
                    v.write_to_with_cached_sizes(os)?;
                },
            };
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for MessageProto {
    fn new() -> MessageProto {
        MessageProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<MessageProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor::<_, BroadcastProto>(
                    "broadcast",
                    MessageProto::has_broadcast,
                    MessageProto::get_broadcast,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor::<_, AgreementProto>(
                    "agreement",
                    MessageProto::has_agreement,
                    MessageProto::get_agreement,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<MessageProto>(
                    "MessageProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for MessageProto {
    fn clear(&mut self) {
        self.clear_broadcast();
        self.clear_agreement();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for MessageProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for MessageProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct BroadcastProto {
    // message oneof groups
    payload: ::std::option::Option<BroadcastProto_oneof_payload>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for BroadcastProto {}

#[derive(Clone,PartialEq)]
pub enum BroadcastProto_oneof_payload {
    value(ValueProto),
    echo(EchoProto),
    ready(ReadyProto),
}

impl BroadcastProto {
    pub fn new() -> BroadcastProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static BroadcastProto {
        static mut instance: ::protobuf::lazy::Lazy<BroadcastProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const BroadcastProto,
        };
        unsafe {
            instance.get(BroadcastProto::new)
        }
    }

    // .ValueProto value = 1;

    pub fn clear_value(&mut self) {
        self.payload = ::std::option::Option::None;
    }

    pub fn has_value(&self) -> bool {
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::value(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_value(&mut self, v: ValueProto) {
        self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::value(v))
    }

    // Mutable pointer to the field.
    pub fn mut_value(&mut self) -> &mut ValueProto {
        if let ::std::option::Option::Some(BroadcastProto_oneof_payload::value(_)) = self.payload {
        } else {
            self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::value(ValueProto::new()));
        }
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::value(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_value(&mut self) -> ValueProto {
        if self.has_value() {
            match self.payload.take() {
                ::std::option::Option::Some(BroadcastProto_oneof_payload::value(v)) => v,
                _ => panic!(),
            }
        } else {
            ValueProto::new()
        }
    }

    pub fn get_value(&self) -> &ValueProto {
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::value(ref v)) => v,
            _ => ValueProto::default_instance(),
        }
    }

    // .EchoProto echo = 2;

    pub fn clear_echo(&mut self) {
        self.payload = ::std::option::Option::None;
    }

    pub fn has_echo(&self) -> bool {
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_echo(&mut self, v: EchoProto) {
        self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(v))
    }

    // Mutable pointer to the field.
    pub fn mut_echo(&mut self) -> &mut EchoProto {
        if let ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(_)) = self.payload {
        } else {
            self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(EchoProto::new()));
        }
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_echo(&mut self) -> EchoProto {
        if self.has_echo() {
            match self.payload.take() {
                ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(v)) => v,
                _ => panic!(),
            }
        } else {
            EchoProto::new()
        }
    }

    pub fn get_echo(&self) -> &EchoProto {
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(ref v)) => v,
            _ => EchoProto::default_instance(),
        }
    }

    // .ReadyProto ready = 3;

    pub fn clear_ready(&mut self) {
        self.payload = ::std::option::Option::None;
    }

    pub fn has_ready(&self) -> bool {
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_ready(&mut self, v: ReadyProto) {
        self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(v))
    }

    // Mutable pointer to the field.
    pub fn mut_ready(&mut self) -> &mut ReadyProto {
        if let ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(_)) = self.payload {
        } else {
            self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(ReadyProto::new()));
        }
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_ready(&mut self) -> ReadyProto {
        if self.has_ready() {
            match self.payload.take() {
                ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(v)) => v,
                _ => panic!(),
            }
        } else {
            ReadyProto::new()
        }
    }

    pub fn get_ready(&self) -> &ReadyProto {
        match self.payload {
            ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(ref v)) => v,
            _ => ReadyProto::default_instance(),
        }
    }
}

impl ::protobuf::Message for BroadcastProto {
    fn is_initialized(&self) -> bool {
        if let Some(BroadcastProto_oneof_payload::value(ref v)) = self.payload {
            if !v.is_initialized() {
                return false;
            }
        }
        if let Some(BroadcastProto_oneof_payload::echo(ref v)) = self.payload {
            if !v.is_initialized() {
                return false;
            }
        }
        if let Some(BroadcastProto_oneof_payload::ready(ref v)) = self.payload {
            if !v.is_initialized() {
                return false;
            }
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::value(is.read_message()?));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::echo(is.read_message()?));
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    self.payload = ::std::option::Option::Some(BroadcastProto_oneof_payload::ready(is.read_message()?));
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let ::std::option::Option::Some(ref v) = self.payload {
            match v {
                &BroadcastProto_oneof_payload::value(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &BroadcastProto_oneof_payload::echo(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &BroadcastProto_oneof_payload::ready(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
            };
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let ::std::option::Option::Some(ref v) = self.payload {
            match v {
                &BroadcastProto_oneof_payload::value(ref v) => {
                    os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
                    os.write_raw_varint32(v.get_cached_size())?;
                    v.write_to_with_cached_sizes(os)?;
                },
                &BroadcastProto_oneof_payload::echo(ref v) => {
                    os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
                    os.write_raw_varint32(v.get_cached_size())?;
                    v.write_to_with_cached_sizes(os)?;
                },
                &BroadcastProto_oneof_payload::ready(ref v) => {
                    os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited)?;
                    os.write_raw_varint32(v.get_cached_size())?;
                    v.write_to_with_cached_sizes(os)?;
                },
            };
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for BroadcastProto {
    fn new() -> BroadcastProto {
        BroadcastProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<BroadcastProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor::<_, ValueProto>(
                    "value",
                    BroadcastProto::has_value,
                    BroadcastProto::get_value,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor::<_, EchoProto>(
                    "echo",
                    BroadcastProto::has_echo,
                    BroadcastProto::get_echo,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor::<_, ReadyProto>(
                    "ready",
                    BroadcastProto::has_ready,
                    BroadcastProto::get_ready,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<BroadcastProto>(
                    "BroadcastProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for BroadcastProto {
    fn clear(&mut self) {
        self.clear_value();
        self.clear_echo();
        self.clear_ready();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for BroadcastProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BroadcastProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ValueProto {
    // message fields
    pub proof: ::protobuf::SingularPtrField<ProofProto>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ValueProto {}

impl ValueProto {
    pub fn new() -> ValueProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ValueProto {
        static mut instance: ::protobuf::lazy::Lazy<ValueProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ValueProto,
        };
        unsafe {
            instance.get(ValueProto::new)
        }
    }

    // .ProofProto proof = 1;

    pub fn clear_proof(&mut self) {
        self.proof.clear();
    }

    pub fn has_proof(&self) -> bool {
        self.proof.is_some()
    }

    // Param is passed by value, moved
    pub fn set_proof(&mut self, v: ProofProto) {
        self.proof = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_proof(&mut self) -> &mut ProofProto {
        if self.proof.is_none() {
            self.proof.set_default();
        }
        self.proof.as_mut().unwrap()
    }

    // Take field
    pub fn take_proof(&mut self) -> ProofProto {
        self.proof.take().unwrap_or_else(|| ProofProto::new())
    }

    pub fn get_proof(&self) -> &ProofProto {
        self.proof.as_ref().unwrap_or_else(|| ProofProto::default_instance())
    }

    fn get_proof_for_reflect(&self) -> &::protobuf::SingularPtrField<ProofProto> {
        &self.proof
    }

    fn mut_proof_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<ProofProto> {
        &mut self.proof
    }
}

impl ::protobuf::Message for ValueProto {
    fn is_initialized(&self) -> bool {
        for v in &self.proof {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.proof)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.proof.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.proof.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ValueProto {
    fn new() -> ValueProto {
        ValueProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<ValueProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<ProofProto>>(
                    "proof",
                    ValueProto::get_proof_for_reflect,
                    ValueProto::mut_proof_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ValueProto>(
                    "ValueProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ValueProto {
    fn clear(&mut self) {
        self.clear_proof();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ValueProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ValueProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct EchoProto {
    // message fields
    pub proof: ::protobuf::SingularPtrField<ProofProto>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for EchoProto {}

impl EchoProto {
    pub fn new() -> EchoProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static EchoProto {
        static mut instance: ::protobuf::lazy::Lazy<EchoProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const EchoProto,
        };
        unsafe {
            instance.get(EchoProto::new)
        }
    }

    // .ProofProto proof = 1;

    pub fn clear_proof(&mut self) {
        self.proof.clear();
    }

    pub fn has_proof(&self) -> bool {
        self.proof.is_some()
    }

    // Param is passed by value, moved
    pub fn set_proof(&mut self, v: ProofProto) {
        self.proof = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_proof(&mut self) -> &mut ProofProto {
        if self.proof.is_none() {
            self.proof.set_default();
        }
        self.proof.as_mut().unwrap()
    }

    // Take field
    pub fn take_proof(&mut self) -> ProofProto {
        self.proof.take().unwrap_or_else(|| ProofProto::new())
    }

    pub fn get_proof(&self) -> &ProofProto {
        self.proof.as_ref().unwrap_or_else(|| ProofProto::default_instance())
    }

    fn get_proof_for_reflect(&self) -> &::protobuf::SingularPtrField<ProofProto> {
        &self.proof
    }

    fn mut_proof_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<ProofProto> {
        &mut self.proof
    }
}

impl ::protobuf::Message for EchoProto {
    fn is_initialized(&self) -> bool {
        for v in &self.proof {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.proof)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.proof.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.proof.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for EchoProto {
    fn new() -> EchoProto {
        EchoProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<EchoProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<ProofProto>>(
                    "proof",
                    EchoProto::get_proof_for_reflect,
                    EchoProto::mut_proof_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<EchoProto>(
                    "EchoProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for EchoProto {
    fn clear(&mut self) {
        self.clear_proof();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for EchoProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EchoProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ReadyProto {
    // message fields
    pub root_hash: ::std::vec::Vec<u8>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ReadyProto {}

impl ReadyProto {
    pub fn new() -> ReadyProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ReadyProto {
        static mut instance: ::protobuf::lazy::Lazy<ReadyProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ReadyProto,
        };
        unsafe {
            instance.get(ReadyProto::new)
        }
    }

    // bytes root_hash = 1;

    pub fn clear_root_hash(&mut self) {
        self.root_hash.clear();
    }

    // Param is passed by value, moved
    pub fn set_root_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.root_hash = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_root_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.root_hash
    }

    // Take field
    pub fn take_root_hash(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.root_hash, ::std::vec::Vec::new())
    }

    pub fn get_root_hash(&self) -> &[u8] {
        &self.root_hash
    }

    fn get_root_hash_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.root_hash
    }

    fn mut_root_hash_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.root_hash
    }
}

impl ::protobuf::Message for ReadyProto {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.root_hash)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.root_hash.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.root_hash);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if !self.root_hash.is_empty() {
            os.write_bytes(1, &self.root_hash)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ReadyProto {
    fn new() -> ReadyProto {
        ReadyProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<ReadyProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "root_hash",
                    ReadyProto::get_root_hash_for_reflect,
                    ReadyProto::mut_root_hash_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ReadyProto>(
                    "ReadyProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ReadyProto {
    fn clear(&mut self) {
        self.clear_root_hash();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ReadyProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ReadyProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ProofProto {
    // message fields
    pub root_hash: ::std::vec::Vec<u8>,
    pub lemma: ::protobuf::SingularPtrField<LemmaProto>,
    pub value: ::std::vec::Vec<u8>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ProofProto {}

impl ProofProto {
    pub fn new() -> ProofProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ProofProto {
        static mut instance: ::protobuf::lazy::Lazy<ProofProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ProofProto,
        };
        unsafe {
            instance.get(ProofProto::new)
        }
    }

    // bytes root_hash = 1;

    pub fn clear_root_hash(&mut self) {
        self.root_hash.clear();
    }

    // Param is passed by value, moved
    pub fn set_root_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.root_hash = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_root_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.root_hash
    }

    // Take field
    pub fn take_root_hash(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.root_hash, ::std::vec::Vec::new())
    }

    pub fn get_root_hash(&self) -> &[u8] {
        &self.root_hash
    }

    fn get_root_hash_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.root_hash
    }

    fn mut_root_hash_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.root_hash
    }

    // .LemmaProto lemma = 2;

    pub fn clear_lemma(&mut self) {
        self.lemma.clear();
    }

    pub fn has_lemma(&self) -> bool {
        self.lemma.is_some()
    }

    // Param is passed by value, moved
    pub fn set_lemma(&mut self, v: LemmaProto) {
        self.lemma = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_lemma(&mut self) -> &mut LemmaProto {
        if self.lemma.is_none() {
            self.lemma.set_default();
        }
        self.lemma.as_mut().unwrap()
    }

    // Take field
    pub fn take_lemma(&mut self) -> LemmaProto {
        self.lemma.take().unwrap_or_else(|| LemmaProto::new())
    }

    pub fn get_lemma(&self) -> &LemmaProto {
        self.lemma.as_ref().unwrap_or_else(|| LemmaProto::default_instance())
    }

    fn get_lemma_for_reflect(&self) -> &::protobuf::SingularPtrField<LemmaProto> {
        &self.lemma
    }

    fn mut_lemma_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<LemmaProto> {
        &mut self.lemma
    }

    // bytes value = 3;

    pub fn clear_value(&mut self) {
        self.value.clear();
    }

    // Param is passed by value, moved
    pub fn set_value(&mut self, v: ::std::vec::Vec<u8>) {
        self.value = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_value(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.value
    }

    // Take field
    pub fn take_value(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.value, ::std::vec::Vec::new())
    }

    pub fn get_value(&self) -> &[u8] {
        &self.value
    }

    fn get_value_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.value
    }

    fn mut_value_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.value
    }
}

impl ::protobuf::Message for ProofProto {
    fn is_initialized(&self) -> bool {
        for v in &self.lemma {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.root_hash)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.lemma)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.value)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.root_hash.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.root_hash);
        }
        if let Some(ref v) = self.lemma.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if !self.value.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.value);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if !self.root_hash.is_empty() {
            os.write_bytes(1, &self.root_hash)?;
        }
        if let Some(ref v) = self.lemma.as_ref() {
            os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if !self.value.is_empty() {
            os.write_bytes(3, &self.value)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ProofProto {
    fn new() -> ProofProto {
        ProofProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<ProofProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "root_hash",
                    ProofProto::get_root_hash_for_reflect,
                    ProofProto::mut_root_hash_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<LemmaProto>>(
                    "lemma",
                    ProofProto::get_lemma_for_reflect,
                    ProofProto::mut_lemma_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "value",
                    ProofProto::get_value_for_reflect,
                    ProofProto::mut_value_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ProofProto>(
                    "ProofProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ProofProto {
    fn clear(&mut self) {
        self.clear_root_hash();
        self.clear_lemma();
        self.clear_value();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ProofProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ProofProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct LemmaProto {
    // message fields
    pub node_hash: ::std::vec::Vec<u8>,
    pub sub_lemma: ::protobuf::SingularPtrField<LemmaProto>,
    // message oneof groups
    sibling_hash: ::std::option::Option<LemmaProto_oneof_sibling_hash>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for LemmaProto {}

#[derive(Clone,PartialEq)]
pub enum LemmaProto_oneof_sibling_hash {
    left_sibling_hash(::std::vec::Vec<u8>),
    right_sibling_hash(::std::vec::Vec<u8>),
}

impl LemmaProto {
    pub fn new() -> LemmaProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static LemmaProto {
        static mut instance: ::protobuf::lazy::Lazy<LemmaProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const LemmaProto,
        };
        unsafe {
            instance.get(LemmaProto::new)
        }
    }

    // bytes node_hash = 1;

    pub fn clear_node_hash(&mut self) {
        self.node_hash.clear();
    }

    // Param is passed by value, moved
    pub fn set_node_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.node_hash = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_node_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.node_hash
    }

    // Take field
    pub fn take_node_hash(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.node_hash, ::std::vec::Vec::new())
    }

    pub fn get_node_hash(&self) -> &[u8] {
        &self.node_hash
    }

    fn get_node_hash_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.node_hash
    }

    fn mut_node_hash_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.node_hash
    }

    // .LemmaProto sub_lemma = 2;

    pub fn clear_sub_lemma(&mut self) {
        self.sub_lemma.clear();
    }

    pub fn has_sub_lemma(&self) -> bool {
        self.sub_lemma.is_some()
    }

    // Param is passed by value, moved
    pub fn set_sub_lemma(&mut self, v: LemmaProto) {
        self.sub_lemma = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_sub_lemma(&mut self) -> &mut LemmaProto {
        if self.sub_lemma.is_none() {
            self.sub_lemma.set_default();
        }
        self.sub_lemma.as_mut().unwrap()
    }

    // Take field
    pub fn take_sub_lemma(&mut self) -> LemmaProto {
        self.sub_lemma.take().unwrap_or_else(|| LemmaProto::new())
    }

    pub fn get_sub_lemma(&self) -> &LemmaProto {
        self.sub_lemma.as_ref().unwrap_or_else(|| LemmaProto::default_instance())
    }

    fn get_sub_lemma_for_reflect(&self) -> &::protobuf::SingularPtrField<LemmaProto> {
        &self.sub_lemma
    }

    fn mut_sub_lemma_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<LemmaProto> {
        &mut self.sub_lemma
    }

    // bytes left_sibling_hash = 3;

    pub fn clear_left_sibling_hash(&mut self) {
        self.sibling_hash = ::std::option::Option::None;
    }

    pub fn has_left_sibling_hash(&self) -> bool {
        match self.sibling_hash {
            ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_left_sibling_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.sibling_hash = ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(v))
    }

    // Mutable pointer to the field.
    pub fn mut_left_sibling_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if let ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(_)) = self.sibling_hash {
        } else {
            self.sibling_hash = ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(::std::vec::Vec::new()));
        }
        match self.sibling_hash {
            ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_left_sibling_hash(&mut self) -> ::std::vec::Vec<u8> {
        if self.has_left_sibling_hash() {
            match self.sibling_hash.take() {
                ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(v)) => v,
                _ => panic!(),
            }
        } else {
            ::std::vec::Vec::new()
        }
    }

    pub fn get_left_sibling_hash(&self) -> &[u8] {
        match self.sibling_hash {
            ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(ref v)) => v,
            _ => &[],
        }
    }

    // bytes right_sibling_hash = 4;

    pub fn clear_right_sibling_hash(&mut self) {
        self.sibling_hash = ::std::option::Option::None;
    }

    pub fn has_right_sibling_hash(&self) -> bool {
        match self.sibling_hash {
            ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_right_sibling_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.sibling_hash = ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(v))
    }

    // Mutable pointer to the field.
    pub fn mut_right_sibling_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if let ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(_)) = self.sibling_hash {
        } else {
            self.sibling_hash = ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(::std::vec::Vec::new()));
        }
        match self.sibling_hash {
            ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_right_sibling_hash(&mut self) -> ::std::vec::Vec<u8> {
        if self.has_right_sibling_hash() {
            match self.sibling_hash.take() {
                ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(v)) => v,
                _ => panic!(),
            }
        } else {
            ::std::vec::Vec::new()
        }
    }

    pub fn get_right_sibling_hash(&self) -> &[u8] {
        match self.sibling_hash {
            ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(ref v)) => v,
            _ => &[],
        }
    }
}

impl ::protobuf::Message for LemmaProto {
    fn is_initialized(&self) -> bool {
        for v in &self.sub_lemma {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.node_hash)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.sub_lemma)?;
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    self.sibling_hash = ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::left_sibling_hash(is.read_bytes()?));
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    self.sibling_hash = ::std::option::Option::Some(LemmaProto_oneof_sibling_hash::right_sibling_hash(is.read_bytes()?));
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.node_hash.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.node_hash);
        }
        if let Some(ref v) = self.sub_lemma.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let ::std::option::Option::Some(ref v) = self.sibling_hash {
            match v {
                &LemmaProto_oneof_sibling_hash::left_sibling_hash(ref v) => {
                    my_size += ::protobuf::rt::bytes_size(3, &v);
                },
                &LemmaProto_oneof_sibling_hash::right_sibling_hash(ref v) => {
                    my_size += ::protobuf::rt::bytes_size(4, &v);
                },
            };
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if !self.node_hash.is_empty() {
            os.write_bytes(1, &self.node_hash)?;
        }
        if let Some(ref v) = self.sub_lemma.as_ref() {
            os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let ::std::option::Option::Some(ref v) = self.sibling_hash {
            match v {
                &LemmaProto_oneof_sibling_hash::left_sibling_hash(ref v) => {
                    os.write_bytes(3, v)?;
                },
                &LemmaProto_oneof_sibling_hash::right_sibling_hash(ref v) => {
                    os.write_bytes(4, v)?;
                },
            };
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for LemmaProto {
    fn new() -> LemmaProto {
        LemmaProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<LemmaProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "node_hash",
                    LemmaProto::get_node_hash_for_reflect,
                    LemmaProto::mut_node_hash_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<LemmaProto>>(
                    "sub_lemma",
                    LemmaProto::get_sub_lemma_for_reflect,
                    LemmaProto::mut_sub_lemma_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor::<_>(
                    "left_sibling_hash",
                    LemmaProto::has_left_sibling_hash,
                    LemmaProto::get_left_sibling_hash,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor::<_>(
                    "right_sibling_hash",
                    LemmaProto::has_right_sibling_hash,
                    LemmaProto::get_right_sibling_hash,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<LemmaProto>(
                    "LemmaProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for LemmaProto {
    fn clear(&mut self) {
        self.clear_node_hash();
        self.clear_sub_lemma();
        self.clear_left_sibling_hash();
        self.clear_right_sibling_hash();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for LemmaProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for LemmaProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct AgreementProto {
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for AgreementProto {}

impl AgreementProto {
    pub fn new() -> AgreementProto {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static AgreementProto {
        static mut instance: ::protobuf::lazy::Lazy<AgreementProto> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const AgreementProto,
        };
        unsafe {
            instance.get(AgreementProto::new)
        }
    }
}

impl ::protobuf::Message for AgreementProto {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for AgreementProto {
    fn new() -> AgreementProto {
        AgreementProto::new()
    }

    fn descriptor_static(_: ::std::option::Option<AgreementProto>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let fields = ::std::vec::Vec::new();
                ::protobuf::reflect::MessageDescriptor::new::<AgreementProto>(
                    "AgreementProto",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for AgreementProto {
    fn clear(&mut self) {
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for AgreementProto {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for AgreementProto {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\rmessage.proto\"{\n\x0cMessageProto\x12/\n\tbroadcast\x18\x01\x20\x01\
    (\x0b2\x0f.BroadcastProtoH\0R\tbroadcast\x12/\n\tagreement\x18\x02\x20\
    \x01(\x0b2\x0f.AgreementProtoH\0R\tagreementB\t\n\x07payload\"\x87\x01\n\
    \x0eBroadcastProto\x12#\n\x05value\x18\x01\x20\x01(\x0b2\x0b.ValueProtoH\
    \0R\x05value\x12\x20\n\x04echo\x18\x02\x20\x01(\x0b2\n.EchoProtoH\0R\x04\
    echo\x12#\n\x05ready\x18\x03\x20\x01(\x0b2\x0b.ReadyProtoH\0R\x05readyB\
    \t\n\x07payload\"/\n\nValueProto\x12!\n\x05proof\x18\x01\x20\x01(\x0b2\
    \x0b.ProofProtoR\x05proof\".\n\tEchoProto\x12!\n\x05proof\x18\x01\x20\
    \x01(\x0b2\x0b.ProofProtoR\x05proof\")\n\nReadyProto\x12\x1b\n\troot_has\
    h\x18\x01\x20\x01(\x0cR\x08rootHash\"b\n\nProofProto\x12\x1b\n\troot_has\
    h\x18\x01\x20\x01(\x0cR\x08rootHash\x12!\n\x05lemma\x18\x02\x20\x01(\x0b\
    2\x0b.LemmaProtoR\x05lemma\x12\x14\n\x05value\x18\x03\x20\x01(\x0cR\x05v\
    alue\"\xc1\x01\n\nLemmaProto\x12\x1b\n\tnode_hash\x18\x01\x20\x01(\x0cR\
    \x08nodeHash\x12(\n\tsub_lemma\x18\x02\x20\x01(\x0b2\x0b.LemmaProtoR\x08\
    subLemma\x12,\n\x11left_sibling_hash\x18\x03\x20\x01(\x0cH\0R\x0fleftSib\
    lingHash\x12.\n\x12right_sibling_hash\x18\x04\x20\x01(\x0cH\0R\x10rightS\
    iblingHashB\x0e\n\x0csibling_hash\"\x10\n\x0eAgreementProtob\x06proto3\
";

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
