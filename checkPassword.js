const bcrypt = require('bcrypt');

const hash = "$2b$10$lzVFiFVUJSb3hRI1cPk/3ej.jAqTx91Yd6Ag5nMalvbgBUa2Fk6He";
const password = "123456";

bcrypt.compare(password, hash).then(result => {
    console.log("Coincide la contraseña?", result);
}).catch(err => {
    console.error("Error al comprobar contraseña:", err);
});
