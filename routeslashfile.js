const colorPicker = document.getElementById("colorPicker")
colorPicker.addEventListener("input", function () {
  const r = parseInt(colorPicker.value.substring(1, 3),16);
  const g = parseInt(colorPicker.value.substring(3, 5),16);
  const b = parseInt(colorPicker.value.substring(5, 7),16);
  fetch(`http://127.0.0.1:5000/i?i=rgb(${r},${g},${b})`);
});