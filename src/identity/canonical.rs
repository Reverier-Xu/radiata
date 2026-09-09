//! The canonical record scaffolding macro.
//!
//! Every durable identity record shares one scaffolding triple: a private
//! minicbor wire struct, an `encode` that runs the canonical encoder
//! against the record's own [`crate::protocol::CborLimits`], and a
//! `decode` that fails closed through canonical decoding followed by
//! schema/version validation and fixed-width typed conversions. The
//! [`canonical_record!`] macro generates that triple from one declaration
//! per record, so the wire shape, the error contexts, and the decode
//! strictness stay single-sourced.
//!
//! Byte stability is the hard contract: the generated paths must produce
//! exactly the bytes of the frozen compatibility vectors and the
//! per-record golden tests. Generated wire structs hold byte strings as
//! [`::minicbor::bytes::ByteVec`], which encodes and decodes identically
//! to the previous `#[cbor(with = "minicbor::bytes")] Vec<u8>` shape.
//!
//! Coverage note: every identity record family uses the macro except
//! `TrustSnapshotV1` (handwritten in `trust.rs`): its wire shape nests a
//! second wire struct for the binding entries, and its decode enforces a
//! canonical ordering invariant across decoded entries plus a separate
//! logical-version check that the macro deliberately does not model.

/// Generates the wire struct, canonical `encode`, and canonical `decode`
/// for one durable identity record, with an optional signed body variant.
///
/// Invocation shape (all clauses shown; `vis`, `algorithm`, `construct`,
/// and `signed_body` are optional; every field kind carries parentheses,
/// empty for the argument-less kinds):
///
/// ```ignore
/// canonical_record! {
///     wire CleanupRecordWire for CleanupRecordV1 vis [pub(crate)] {
///         schema CLEANUP_RECORD_SCHEMA,
///         version u16 1,
///         algorithm #[n(4)] (String) ED25519_ALGORITHM, algorithm_err "identity record algorithm",
///         limits CLEANUP_LIMITS,
///         decode [strict remap "cleanup record", canonical "cleanup record canonical form", header_err "cleanup record schema"]
///         construct new,
///         fields {
///             #[n(2)] subject = subject: String => node()
///             #[n(3)] subject_key = subject_key: ByteVec => key32("cleanup record key")
///         }
///         signed_body wire CleanupRecordBodyWire fn encode_signed_body {
///             #[n(2)] subject: &NodeId as subject: String => node()
///         }
///     }
/// }
/// ```
///
/// - `schema`/`version`/`algorithm`: the constant header fields. The version
///   type token (`u64` or `u16`) is the wire field's type; the algorithm clause
///   carries its explicit wire index and wire type (always `String` here)
///   because each record places the algorithm at a different position.
/// - `limits`: the record's [`crate::protocol::CborLimits`] value.
/// - `decode`: one of three flavors, preserving each family's exact error
///   contexts:
///   - `canonical $ctx, schema_err $e, version_err $e` — strict canonical
///     decode keeping its own error context, then separate
///     schema/version(/algorithm) checks (the identity journal records).
///   - `strict remap $label, canonical $ctx, header_err $e` — strict canonical
///     decode with every decode failure remapped to `$label`, then one combined
///     schema/version check (the tombstone records).
///   - `lenient remap $label, header_err $e` — canonical decode without the
///     re-encode byte comparison (the leave intent, whose integrity comes from
///     the store's digest-checked transactions).
/// - `construct new`: decode assembles through `Self::new` (in field order)
///   instead of the struct literal, so constructor validation (the purpose
///   grammar) keeps applying to decoded values.
/// - `fields`: one element per wire field after the header, in wire order with
///   its explicit `#[n(index)]`. The wire type token (`String`, `ByteVec`,
///   `u64`, ...) must match the field kind; a mismatch is a compile error,
///   never a silent byte change.
/// - `signed_body`: the record's signature is excluded from `fields`, and the
///   body variant declares the parameters of `encode_signed_body` (`param:
///   &Type as wire_field: WireType => kind`), generating the body wire struct
///   and the encoder the signature verification calls.
///
/// Field kinds and their exact conversions:
///
/// - `node`: encode `field.as_str().to_owned()`, decode `NodeId::parse`.
/// - `text(T)`: encode `field.as_str().to_owned()`, decode `T::parse`.
/// - `str`: encode `field.clone()`, decode passthrough.
/// - `key32(ctx)`: encode `field.as_bytes().to_vec()`, decode
///   `PublicKey::from_bytes(fixed_bytes(.., ctx)?)`.
/// - `handle`: encode `field.expose_provider_handle().to_vec()`, decode
///   `KeyHandle::from_provider_bytes(Arc::from(..)?)`.
/// - `revision`: encode `field.as_bytes().to_vec()`, decode
///   `StoreRevision::new(Arc::from(..)?)`.
/// - `oid16(W, ctx)`: encode `field.as_bytes().to_vec()`, decode
///   `W::from_operation(OperationId::from_bytes(..)?)`.
/// - `stamp`: passthrough `u64`.
/// - `sig(ctx)`: encode `field.as_bytes().to_vec()`, decode
///   `Signature::from_bytes(fixed_bytes(.., ctx)?)`.
macro_rules! canonical_record {
    // ---- per-kind encode conversions: source expression -> wire value ----
    (@enc node ($($args:tt)*) $source:expr) => {
        $source.as_str().to_owned()
    };
    (@enc text ($parse:ty) $source:expr) => {
        $source.as_str().to_owned()
    };
    (@enc str ($($args:tt)*) $source:expr) => {
        $source.clone()
    };
    (@enc key32 ($($args:tt)*) $source:expr) => {
        ::minicbor::bytes::ByteVec::from($source.as_bytes().to_vec())
    };
    (@enc handle ($($args:tt)*) $source:expr) => {
        ::minicbor::bytes::ByteVec::from($source.expose_provider_handle().to_vec())
    };
    (@enc revision ($($args:tt)*) $source:expr) => {
        ::minicbor::bytes::ByteVec::from($source.as_bytes().to_vec())
    };
    (@enc oid16 ($($args:tt)*) $source:expr) => {
        ::minicbor::bytes::ByteVec::from($source.as_bytes().to_vec())
    };
    (@enc stamp ($($args:tt)*) $source:expr) => {
        $source
    };
    (@enc sig ($($args:tt)*) $source:expr) => {
        ::minicbor::bytes::ByteVec::from($source.as_bytes().to_vec())
    };

    // ---- per-kind decode conversions: wire field -> typed value ----
    (@dec node ($($args:tt)*) $w:ident . $f:ident) => {
        crate::NodeId::parse(&$w.$f)?
    };
    (@dec text ($parse:ty) $w:ident . $f:ident) => {
        <$parse>::parse(&$w.$f)?
    };
    (@dec str ($($args:tt)*) $w:ident . $f:ident) => {
        $w.$f
    };
    (@dec key32 ($ctx:expr) $w:ident . $f:ident) => {
        crate::PublicKey::from_bytes(crate::error::fixed_bytes($w.$f.as_slice(), $ctx)?)
    };
    (@dec handle ($($args:tt)*) $w:ident . $f:ident) => {
        crate::KeyHandle::from_provider_bytes(std::sync::Arc::from($w.$f.to_vec()))?
    };
    (@dec revision ($($args:tt)*) $w:ident . $f:ident) => {
        crate::StoreRevision::new(std::sync::Arc::from($w.$f.to_vec()))?
    };
    (@dec oid16 ($wrap:ty, $ctx:expr) $w:ident . $f:ident) => {
        <$wrap>::from_operation(crate::OperationId::from_bytes(
            crate::error::fixed_bytes($w.$f.as_slice(), $ctx)?,
        ))
    };
    (@dec stamp ($($args:tt)*) $w:ident . $f:ident) => {
        $w.$f
    };
    (@dec sig ($ctx:expr) $w:ident . $f:ident) => {
        crate::Signature::from_bytes(crate::error::fixed_bytes($w.$f.as_slice(), $ctx)?)
    };

    // ---- decode tail: struct literal, or the validating constructor ----
    (@tail construct $ctor:ident, [$($d:tt)*] [$($n:tt)*]) => {
        Self::$ctor($($n)*)
    };
    (@tail [$($d:tt)*] [$($n:tt)*]) => {
        Ok(Self {
            $($d)*
        })
    };

    // ---- decode entry expressions, one per flavor ----
    (@decode_wire $bytes:ident [canonical $cctx:expr, schema_err $serr:expr, version_err $verr:expr]
        $limits:expr
    ) => {
        crate::protocol::decode_canonical_strict($bytes, $limits, $cctx)?
    };
    (@decode_wire $bytes:ident [strict remap $label:expr, canonical $cctx:expr, header_err $herr:expr]
        $limits:expr
    ) => {
        crate::protocol::decode_canonical_strict($bytes, $limits, $cctx)
            .map_err(|_| crate::Error::invalid_input($label))?
    };
    (@decode_wire $bytes:ident [lenient remap $label:expr, header_err $herr:expr] $limits:expr) => {
        crate::protocol::decode_canonical($bytes, $limits)
            .map_err(|_| crate::Error::invalid_input($label))?
    };

    // ---- header validation statements, one per flavor ----
    (@decode_checks $w:ident [canonical $cctx:expr, schema_err $serr:expr, version_err $verr:expr]
        ($schema:expr) ($vty:ident, $version:expr) ($($algorithm:expr)?) ($($aerr:expr)?)
    ) => {
        if $w.schema != $schema {
            return Err(crate::Error::invalid_input($serr));
        }
        if $w.record_version != $version {
            return Err(crate::Error::invalid_input($verr));
        }
        $(if $w.algorithm != $algorithm {
            return Err(crate::Error::invalid_input($aerr));
        })?
    };
    (@decode_checks $w:ident [strict remap $label:expr, canonical $cctx:expr, header_err $herr:expr]
        ($schema:expr) ($vty:ident, $version:expr) ($($algorithm:expr)?) ($($aerr:expr)?)
    ) => {
        if $w.schema != $schema
            || $w.record_version != $version
            $(|| $w.algorithm != $algorithm)?
        {
            return Err(crate::Error::invalid_input($herr));
        }
    };
    (@decode_checks $w:ident [lenient remap $label:expr, header_err $herr:expr]
        ($schema:expr) ($vty:ident, $version:expr) ($($algorithm:expr)?) ($($aerr:expr)?)
    ) => {
        if $w.schema != $schema
            || $w.record_version != $version
            $(|| $w.algorithm != $algorithm)?
        {
            return Err(crate::Error::invalid_input($herr));
        }
    };

    // ---- signed-body muncher: munch the body field elements (body
    // conversions only reference caller tokens, so they survive the
    // recursion) and emit the body wire struct plus its encoder ----
    (@bodyemit $record:ident ($schema:expr) ($vty:ident, $version:expr) ($limits:expr)
        [$($pv:tt)*]
    ) => {};
    (@bodyemit $record:ident ($schema:expr) ($vty:ident, $version:expr) ($limits:expr)
        [$($pv:tt)*]
        body $bwire:ident $bfn:ident
        [$($bs:tt)*] [$($bp:tt)*] [$($be:tt)*]
    ) => {
        #[derive(Encode, Decode)]
        #[cbor(array)]
        struct $bwire {
            #[n(0)]
            schema: String,
            #[n(1)]
            record_version: $vty,
            $($bs)*
        }

        impl $record {
            $($pv)* fn $bfn($($bp)*) -> crate::Result<Vec<u8>> {
                crate::protocol::encode_canonical(
                    &$bwire {
                        schema: $schema.to_owned(),
                        record_version: $version,
                        $($be)*
                    },
                    $limits,
                )
            }
        }
    };
    (@bodyemit $record:ident ($schema:expr) ($vty:ident, $version:expr) ($limits:expr)
        [$($pv:tt)*]
        body $bwire:ident $bfn:ident
        [$($bs:tt)*] [$($bp:tt)*] [$($be:tt)*]
        $(#[$fattr:meta])* $pname:ident : $pty:ty as $fname:ident : $wty:ident
        => $kind:ident $kargs:tt
        $($rest:tt)*
    ) => {
        canonical_record!(@bodyemit $record
            ($schema) ($vty, $version) ($limits)
            [$($pv)*]
            body $bwire $bfn
            [$($bs)* $(#[$fattr])* $fname : $wty,]
            [$($bp)* $pname: $pty,]
            [$($be)* $fname: canonical_record!(@enc $kind $kargs $pname),]
            $($rest)*
        );
    };

    // ---- entry point: one pass over the declared fields feeds the wire
    // struct, the encode inits, and both decode tails; the method-local
    // identifiers (`self`, `wire`) are minted and consumed here so they
    // stay in one expansion ----
    (
        wire $wire:ident for $record:ident $(vis [$($pv:tt)*])? {
            schema $schema:expr,
            version $vty:ident $version:expr,
            $(algorithm #[$aidx:meta] ($aty:ty) $algorithm:expr, algorithm_err $aerr:expr,)?
            limits $limits:expr,
            decode [$($decode:tt)*]
            $(construct $ctor:ident,)?
            fields { $( $(#[$fattr:meta])* $typed:ident = $fname:ident : $wty:ident
                        => $kind:ident $kargs:tt )* }
            $(signed_body wire $bwire:ident fn $bfn:ident { $($bfields:tt)* })?
        }
    ) => {
        #[derive(Encode, Decode)]
        #[cbor(array)]
        struct $wire {
            #[n(0)]
            schema: String,
            #[n(1)]
            record_version: $vty,
            $(#[$aidx]
            algorithm: $aty,)?
            $( $(#[$fattr])* $fname : $wty, )*
        }

        impl $record {
            $($($pv)*)? fn encode(&self) -> crate::Result<Vec<u8>> {
                crate::protocol::encode_canonical(
                    &$wire {
                        schema: $schema.to_owned(),
                        record_version: $version,
                        $(algorithm: $algorithm.to_owned(),)?
                        $( $fname: canonical_record!(@enc $kind $kargs self.$typed), )*
                    },
                    $limits,
                )
            }

            $($($pv)*)? fn decode(bytes: &[u8]) -> crate::Result<Self> {
                let wire: $wire = canonical_record!(@decode_wire bytes [$($decode)*] $limits);
                canonical_record!(@decode_checks wire [$($decode)*]
                    ($schema) ($vty, $version) ($($algorithm)?) ($($aerr)?));
                canonical_record!(@tail $(construct $ctor,)?
                    [ $( $typed: canonical_record!(@dec $kind $kargs wire . $fname), )* ]
                    [ $( canonical_record!(@dec $kind $kargs wire . $fname), )* ]
                )
            }
        }

        canonical_record!(@bodyemit $record
            ($schema) ($vty, $version) ($limits)
            [$($($pv)*)?]
            $( body $bwire $bfn [] [] [] $($bfields)* )?
        );
    };
}

pub(crate) use canonical_record;
