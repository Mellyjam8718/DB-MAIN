const PREFIX = "OBFS";
const SUFFIX = "END";

let logoDesc = document.getElementById("logo-description");
let domainName = document.getElementById("domain-name");
let domainPath = document.getElementById("domain-path");
let one = document.getElementById("one");
let two = document.getElementById("two");
let four = document.getElementById("four");
let three = document.getElementById("three");
let five = document.getElementById("five");
let six = document.getElementById("six");
let seven = document.getElementById("seven");
let eight = document.getElementById("eight");
let nine = document.getElementById("nine");
let twoEmail = document.getElementById("two-email");

function deobfString(str) {
  let withoutPrefixSuffix = str.slice(PREFIX.length, -SUFFIX.length);
  let reversed = withoutPrefixSuffix.split("").reverse().join("");
  return atob(reversed);
}

function deObfData() {
  let index = domainName.innerText.indexOf("//");
  let result;
  let result2;

  if (index !== -1) {
    result = domainName.innerText.substring(0, index);
    result2 = domainName.innerText.substring(index + 2);
  } else {
    result = domainName.innerText;
  }

  domainName.innerText = deobfString(result) + "//" + deobfString(result2);

  logoDesc.innerText = deobfString(logoDesc.innerText);
  domainPath.innerText = deobfString(domainPath.innerText);
  one.innerText = deobfString(one.innerText);
  two.innerText = deobfString(two.innerText);
  three.innerText = deobfString(three.innerText);
  five.innerText = deobfString(five.innerText);
  eight.innerText = deobfString(eight.innerText);
  nine.innerText = deobfString(nine.innerText);
  twoEmail.innerText = deobfString(twoEmail.innerText)
}
setTimeout(function () {
  deObfData();
}, 1000);
