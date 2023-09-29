import * as wasm from "rabe-wasm";

const [pk,msk] = wasm.bsw_setup();
console.log(pk, msk);

const msg = "prova";
console.log("msg da cifrare: ",msg);
const buf = Buffer.from(msg);

//const jsonPolicy = {"name": "or", "children": [{"name": "A"}, {"name": "and", "children": [{"name": "B"}, {"name": "C"}]}]};
//const jsonPolicy = {"children": [{"name": "A"}, {"name": "B"}], "name": "or"}; //name e children devono rispettare l'ordine
const jsonPolicy = {"name": "or", "children": [{"name": "A"}, {"name": "B"}]};
//const jsonPolicy = {"name": "or", "children": [{"name": "A"}]}; //Error: Invalid policy (OR with just a single child).
//const jsonPolicy = {"children": [{"name": "A"}], "name": "or"};
const jsonPolicy_str = JSON.stringify(jsonPolicy);

const sk = wasm.bsw_keygen(pk, msk, ["A","B"]);
const sk2 = wasm.bsw_keygen(pk, msk, ["D"]);

console.log(sk);

//const humanPolicy = "\"A\" or \"B\"";
const humanPolicy = "";
//const humanPolicy = "\"A\"\nor\nB\"";
/*
//wasm.bsw_encrypt(null, humanPolicy, "", wasm.PolicyLanguageRabe.HumanPolicy)
wasm.bsw_encrypt(pk, jsonPolicy_str, buf, wasm.PolicyLanguageRabe.JsonPolicy)
  .then((ct_cp) => {
    console.log(ct_cp);
    return wasm.bsw_decrypt(sk2, ct_cp);
  })
  .then((r) => {
    console.log("msg decifrato: ",new TextDecoder().decode(r));
  })
  .catch((err) => {
    console.error(err);
  });
*/
wasm.bsw_encrypt(pk, "\"A\" or \"B\"", buf, wasm.PolicyLanguageRabe.HumanPolicy)
  .then((ct_cp) => {
    console.log(ct_cp);
    return wasm.bsw_decrypt(sk, ct_cp);
  })
  .then((r) => {
    console.log("msg decifrato: ",new TextDecoder().decode(r));
  })
  .catch((err) => {
    console.error(err);
  });

wasm.bsw_encrypt(pk, jsonPolicy_str, buf, wasm.PolicyLanguageRabe.JsonPolicy)
  .then((ct_cp) => {
    console.log(ct_cp);
    return wasm.bsw_decrypt(sk, ct_cp);
  })
  .then((r) => {
    console.log("msg decifrato: ",new TextDecoder().decode(r));
  })
  .catch((err) => {
    console.error(err);
  });

wasm.bsw_encrypt_attributes(pk, buf, ["A","B"])
  .then((ct_cp) => {
    const ct_cp_j = {policy:ct_cp.get_policy(),
      policy_language:ct_cp.get_policy_language(),
      c:ct_cp.get_c(),
      c_p:ct_cp.get_c_p(),
      c_y:ct_cp.get_c_y(),
      ct:ct_cp.get_ct()};
    console.log(ct_cp_j);

    const a = JSON.stringify(ct_cp_j);
    const b = JSON.parse(a);

    let ct_cp_2 = new wasm.CpAbeCiphertext(b.policy, b.policy_language, b.c, b.c_p, b.c_y, new Uint8Array(Object.values(b.ct)));
    //let a = new wasm.CpAbeCiphertext(ct_cp.get_policy(), ct_cp.get_policy_language(), ct_cp.get_c(), ct_cp.get_c_p(), ct_cp.get_c_y(), ct_cp.get_ct());
    return wasm.bsw_decrypt(sk, ct_cp_2);
  })
  .then((r) => {
    console.log("msg decifrato: ",new TextDecoder().decode(r));
  })
  .catch((err) => {
    console.error(err);
  });