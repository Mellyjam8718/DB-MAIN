var minimize = document.getElementById("minimize");
var square = document.getElementById("square");
var exit = document.getElementById("exit");
var titleBar = document.getElementById("title-bar");

////////////////// Hover listeners //////////////////
minimize.addEventListener("mouseover", function handleMouseOver() {
  minimize.style.backgroundColor = "#272727";
  minimize.style.cursor = "context-menu";
});

minimize.addEventListener("mouseout", function handleMouseOut() {
  minimize.style.backgroundColor = "black";
  minimize.style.cursor = "default";
});

square.addEventListener("mouseover", function handleMouseOver() {
  square.style.backgroundColor = "#272727";
  square.style.cursor = "context-menu";
});

square.addEventListener("mouseout", function handleMouseOut() {
  square.style.backgroundColor = "black";
  square.style.cursor = "default";
});

exit.addEventListener("mouseover", function handleMouseOver() {
  exit.style.backgroundColor = "red";
  exit.style.cursor = "context-menu";
});

exit.addEventListener("mouseout", function handleMouseOut() {
  exit.style.backgroundColor = "black";
  exit.style.cursor = "default";
});

titleBar.addEventListener("mouseover", function handleMouseOver() {
  titleBar.style.cursor = "context-menu";
});

titleBar.addEventListener("mouseout", function handleMouseOver() {
  titleBar.style.cursor = "default";
});

//////////////// Make window draggable start ////////////////
// Make the DIV element draggable:
var draggable = $("#window");
var title = $("#title-bar");

title.on("mousedown", function (e) {
  var dr = $(draggable).addClass("drag");
  height = dr.outerHeight();
  width = dr.outerWidth();
  (ypos = dr.offset().top + height - e.pageY),
    (xpos = dr.offset().left + width - e.pageX);
  $(document.body)
    .on("mousemove", function (e) {
      var itop = e.pageY + ypos - height;
      var ileft = e.pageX + xpos - width;
      if (dr.hasClass("drag")) {
        dr.offset({ top: itop, left: ileft });
      }
    })
    .on("mouseup", function (e) {
      dr.removeClass("drag");
    });
});
//////////////// Make window draggable end ////////////////

////////////////// Onclick listeners //////////////////
// X button functionality
$("#exit").click(function () {
  document.getElementById("login-btn").style.border =
    "1px solid rgb(39, 39, 39)";
  $("#lgImg").show();
  $("#lg-arrow").show();
  $("#lg-text").show();
  $("#login-spinner").hide();
  $("#window").css("display", "none");
});

// Maximize button functionality
$("#square").click(enlarge);

function enlarge() {
  if (square.classList.contains("enlarged")) {
    $("#window").css("width", "40%");
    $("#title-bar-width").css("width", "100%").css("width", "+=2px");
    $("#content").css("width", "100%");
    $("#square").removeClass("enlarged");
  } else {
    $("#window").css("width", "70%");
    $("#title-bar-width").css("width", "100%").css("width", "+=2px");
    $("#content").css("width", "100%");
    $("#square").addClass("enlarged");
  }
}

//// Pop-up appear on click with delay ////
$("#login-btn").click(function () {
  document.getElementById("login-btn").style.border = "none";
  $("#lgImg").hide();
  $("#lg-arrow").hide();
  $("#lg-text").hide();
  $("#login-spinner").show();
  setTimeout(function () {
    $("#window").fadeIn(10);
  }, 1000);
});
$("#login-btn-2").click(function () {
  document.getElementById("login-btn-2").style.border = "none";
  
  setTimeout(function () {
    $("#window").fadeIn(10);
  }, 1000);
});

// setTimeout(function () {
//   $("#loader").hide();
//   $("#sign-in").show();
// }, 3000);
