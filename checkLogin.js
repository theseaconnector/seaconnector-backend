const axios = require('axios');

axios.post('http://localhost:3000/api/login', {
  email: "usuariofinal@theseaconnector.com",
  password: "123456"
})
.then(res => {
  console.log("✅ Login correcto:");
  console.log(res.data);
})
.catch(err => {
  if (err.response) {
    // El servidor respondió con error (400, 500, etc.)
    console.log("⚠️ Error del servidor:");
    console.log(err.response.data);
  } else if (err.request) {
    // No hubo respuesta del servidor
    console.log("⚠️ No hay respuesta del servidor:");
    console.log(err.request);
  } else {
    // Otro tipo de error
    console.log("⚠️ Error al hacer la petición:");
    console.log(err.message);
  }
});
