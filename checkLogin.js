const axios = require('axios');

axios.post('https://seaconnector-backend.onrender.com/api/login', {
  email: "usuariofinal@theseaconnector.com",
  password: "123456"
})
.then(res => {
  console.log("LOGIN CORRECTO:");
  console.log("Token:", res.data.token);
  console.log("Usuario:", res.data.user);
})
.catch(err => {
  if (err.response) {
    console.log("Error del servidor (" + err.response.status + "):");
    console.log(err.response.data);
  } else if (err.request) {
    console.log("No hay respuesta del servidor");
    console.log("Status:", err.request.status);
  } else {
    console.log("Error de petición:");
    console.log(err.message);
  }
});