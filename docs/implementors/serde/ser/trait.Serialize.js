(function() {var implementors = {};
implementors["crypto_secretstream"] = [{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"crypto_secretstream/struct.Header.html\" title=\"struct crypto_secretstream::Header\">Header</a>","synthetic":false,"types":["crypto_secretstream::header::Header"]}];
implementors["ecdsa"] = [{"text":"impl&lt;C&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"ecdsa/struct.Signature.html\" title=\"struct ecdsa::Signature\">Signature</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"ecdsa/trait.PrimeCurve.html\" title=\"trait ecdsa::PrimeCurve\">PrimeCurve</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"ecdsa/type.SignatureSize.html\" title=\"type ecdsa::SignatureSize\">SignatureSize</a>&lt;C&gt;: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;,&nbsp;</span>","synthetic":false,"types":["ecdsa::Signature"]}];
implementors["elliptic_curve"] = [{"text":"impl&lt;C&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"elliptic_curve/struct.ScalarCore.html\" title=\"struct elliptic_curve::ScalarCore\">ScalarCore</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,&nbsp;</span>","synthetic":false,"types":["elliptic_curve::scalar::core::ScalarCore"]}];
implementors["generic_array"] = [{"text":"impl&lt;T, N&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;T, N&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;T&gt;,&nbsp;</span>","synthetic":false,"types":["generic_array::GenericArray"]}];
implementors["p256"] = [{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"p256/struct.AffinePoint.html\" title=\"struct p256::AffinePoint\">AffinePoint</a>","synthetic":false,"types":["p256::arithmetic::affine::AffinePoint"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>","synthetic":false,"types":["p256::arithmetic::scalar::Scalar"]}];
implementors["riir_host_tools"] = [{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"riir_host_tools/struct.SignedHash.html\" title=\"struct riir_host_tools::SignedHash\">SignedHash</a>","synthetic":false,"types":["riir_host_tools::packaging::common::SignedHash"]},{"text":"impl&lt;const N:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"riir_host_tools/struct.SignedHashes.html\" title=\"struct riir_host_tools::SignedHashes\">SignedHashes</a>&lt;N&gt;","synthetic":false,"types":["riir_host_tools::packaging::common::SignedHashes"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"riir_host_tools/struct.DynComp.html\" title=\"struct riir_host_tools::DynComp\">DynComp</a>","synthetic":false,"types":["riir_host_tools::packaging::common::DynComp"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"riir_host_tools/struct.ConfigPackage.html\" title=\"struct riir_host_tools::ConfigPackage\">ConfigPackage</a>","synthetic":false,"types":["riir_host_tools::packaging::config::ConfigPackage"]},{"text":"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"riir_host_tools/struct.FirmwarePackage.html\" title=\"struct riir_host_tools::FirmwarePackage\">FirmwarePackage</a>","synthetic":false,"types":["riir_host_tools::packaging::firmware::FirmwarePackage"]}];
implementors["sec1"] = [{"text":"impl&lt;Size&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"sec1/point/struct.EncodedPoint.html\" title=\"struct sec1::point::EncodedPoint\">EncodedPoint</a>&lt;Size&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Size: <a class=\"trait\" href=\"sec1/point/trait.ModulusSize.html\" title=\"trait sec1::point::ModulusSize\">ModulusSize</a>,&nbsp;</span>","synthetic":false,"types":["sec1::point::EncodedPoint"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()