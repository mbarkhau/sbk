(function(){
  'use strict';

  function getOS() {
    var userAgent = window.navigator.userAgent,
        platform = window.navigator.platform,
        macosPlatforms = ['Macintosh', 'MacIntel', 'MacPPC', 'Mac68K'],
        windowsPlatforms = ['Win32', 'Win64', 'Windows', 'WinCE'],
        iosPlatforms = ['iPhone', 'iPad', 'iPod'],
        os = null;

    if (macosPlatforms.indexOf(platform) !== -1) {
      return 'macos';
    } else if (iosPlatforms.indexOf(platform) !== -1) {
      return 'ios';
    } else if (windowsPlatforms.indexOf(platform) !== -1) {
      return 'windows';
    } else if (/Android/.test(userAgent)) {
      return 'android';
    } else if (!os && /Linux/.test(platform)) {
      return 'linux';
    } else {
      return '';
    }
  }

  let selector = ".bootable-tutorial-links ." + getOS();
  document.querySelectorAll(selector).forEach(function (e) {
    e.classList.add("active");
  })

  let headlines = [
    "Split&nbsp;Bitcoin&nbsp;Keys",
    "Secure&nbsp;Brain&nbsp;Keys",
    "Safe&nbsp;Brain&nbsp;Keys",
  ];

  var index = 1;

  function updateHeadline() {
    let headline = headlines[index];
    let node = document.querySelector("h1#fader span:nth-child(2)");
    node.classList.add("fadeout")
    node.classList.remove("fadein");
    setTimeout(function() {
      node.classList.add("fadein");
      node.classList.remove("fadeout");
      node.innerHTML = headline;
    }, 250)
    index = (index + 1) % headlines.length;
  }

  setInterval(updateHeadline, 5000);

})()