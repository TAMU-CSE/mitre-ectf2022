(function() {var implementors = {};
implementors["blake2"] = [{"text":"impl <a class=\"trait\" href=\"crypto_common/trait.OutputSizeUser.html\" title=\"trait crypto_common::OutputSizeUser\">OutputSizeUser</a> for <a class=\"struct\" href=\"blake2/struct.Blake2bVarCore.html\" title=\"struct blake2::Blake2bVarCore\">Blake2bVarCore</a>","synthetic":false,"types":["blake2::Blake2bVarCore"]},{"text":"impl&lt;OutSize&gt; <a class=\"trait\" href=\"crypto_common/trait.OutputSizeUser.html\" title=\"trait crypto_common::OutputSizeUser\">OutputSizeUser</a> for <a class=\"struct\" href=\"blake2/struct.Blake2bMac.html\" title=\"struct blake2::Blake2bMac\">Blake2bMac</a>&lt;OutSize&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;OutSize: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt; + <a class=\"trait\" href=\"typenum/type_operators/trait.IsLessOrEqual.html\" title=\"trait typenum::type_operators::IsLessOrEqual\">IsLessOrEqual</a>&lt;<a class=\"type\" href=\"typenum/generated/consts/type.U64.html\" title=\"type typenum::generated::consts::U64\">U64</a>&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"typenum/operator_aliases/type.LeEq.html\" title=\"type typenum::operator_aliases::LeEq\">LeEq</a>&lt;OutSize, <a class=\"type\" href=\"typenum/generated/consts/type.U64.html\" title=\"type typenum::generated::consts::U64\">U64</a>&gt;: <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,&nbsp;</span>","synthetic":false,"types":["blake2::Blake2bMac"]},{"text":"impl <a class=\"trait\" href=\"crypto_common/trait.OutputSizeUser.html\" title=\"trait crypto_common::OutputSizeUser\">OutputSizeUser</a> for <a class=\"struct\" href=\"blake2/struct.Blake2sVarCore.html\" title=\"struct blake2::Blake2sVarCore\">Blake2sVarCore</a>","synthetic":false,"types":["blake2::Blake2sVarCore"]},{"text":"impl&lt;OutSize&gt; <a class=\"trait\" href=\"crypto_common/trait.OutputSizeUser.html\" title=\"trait crypto_common::OutputSizeUser\">OutputSizeUser</a> for <a class=\"struct\" href=\"blake2/struct.Blake2sMac.html\" title=\"struct blake2::Blake2sMac\">Blake2sMac</a>&lt;OutSize&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;OutSize: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt; + <a class=\"trait\" href=\"typenum/type_operators/trait.IsLessOrEqual.html\" title=\"trait typenum::type_operators::IsLessOrEqual\">IsLessOrEqual</a>&lt;<a class=\"type\" href=\"typenum/generated/consts/type.U32.html\" title=\"type typenum::generated::consts::U32\">U32</a>&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"typenum/operator_aliases/type.LeEq.html\" title=\"type typenum::operator_aliases::LeEq\">LeEq</a>&lt;OutSize, <a class=\"type\" href=\"typenum/generated/consts/type.U32.html\" title=\"type typenum::generated::consts::U32\">U32</a>&gt;: <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,&nbsp;</span>","synthetic":false,"types":["blake2::Blake2sMac"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()