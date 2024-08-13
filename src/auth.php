<?php
/**
 * Interaxion - Clase Auth para manejo de cuentas de usuarios.
 * 
 * @author AndyDevX <andresag253@gmail.com>
 * @copyright 2024 Andrés Ayuso (AndyDevX)
 * @license MIT
 */
namespace interaxion\modules;

use Dotenv\Dotenv;
use interaxion\modules\SessionManager;
use mysqli;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;

class Auth {
    private $connection;
    private $session;

    public function __construct($host, $user, $password, $db) {
        $this -> connection = new mysqli($host, $user, $password, $db);
        $this -> session = new SessionManager();
        $this -> session -> startSession();

        if ($this -> connection -> connect_error) {
            throw new Exception("Error al conectar con la BD: " . $this -> connection -> connect_error);
        }

        //? Cargar las variables de entorno
        $dotenv = Dotenv::createImmutable(__DIR__ . '/../..'); //! AJUSTA LA RUTA SEGÚN TU PROYECTO
        $dotenv->load();
    }

    public function register($email, $username, $password) {
        //? Comprobar disponibilidad de email y username
        $stmt = $this -> connection -> prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt -> bind_param("ss", $username, $email);
        $stmt -> execute();
        $stmt -> store_result();

        if ($stmt -> num_rows > 0) {
            //? Si se encuentra un resultado, significa que ya existe alguno de esos datos, se envía el mensaje de alerta
            $stmt -> close();
            $this -> session -> setNotification("error", "El correo o nombre de usuario ya están en uso.");
            return false;

        } else {
            //? Hasheo de la contraseña
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            //? Generación de token de seguridad
            $token = bin2hex(random_bytes(16));
            //? Añadir caducidad para el token
            $tokenExpiration = date('Y-m-d H:i:s', strtotime('+24 hours'));

            //? Insertar en la DB
            $stmt = $this -> connection -> prepare("INSERT INTO users (username, email, password_hash, token, token_expiration) VALUES (?, ?, ?, ?, ?)");
            $stmt -> bind_param("sssss", $username, $email, $passwordHash, $token, $tokenExpiration);
            
            if (!$stmt -> execute()) {
                //? Error en el registro
                $stmt -> close();
                $this -> session -> setNotification("error", "Error al registrar el usuario, inténtelo de nuevo.");
                return false;
            }

            $stmt -> close();
            //? ENVIAR CORREO DE VERIFICACIÓN PARA ACTIVAR LA CUENTA
            $this -> sendVerification($email, $token);
            $this -> session -> setNotification("success", "Se envió un correo de verificación a la dirección que ingresaste, revisalo para activar tu cuenta.");
            
            return true;
        }
    }

    public function login($email, $password) {
        //? Comprobar la existencia de la cuenta
        $stmt = $this -> connection -> prepare("SELECT * FROM users WHERE email = ?");
        $stmt -> bind_param("s", $email);
        $stmt -> execute();
        $result = $stmt -> get_result();

        if ($result -> num_rows > 0) {
            //? Si se encuentra un resultado, significa que la cuenta existe
            $result = $result -> fetch_assoc();
            $stmt -> close();

            if (password_verify($password, $result['password_hash'])) {
                //? Contraseña correcta
                $this -> session -> set("username", $result["username"]);
                $this -> session -> set("email", $result["email"]);
                $this -> session -> set("islogged", true);
                $this -> session -> setNotification("success", "Bienvenido, {$result['username']}.");
                return true;

            } else {
                //? Contraseña incorrecta
                $this -> session -> setNotification("error", "Contraseña incorrecta");
                return false;
            }
        } else {
            //? Si no se encuentra un resultado, significa que la cuenta no existe
            $stmt -> close();
            $this -> session -> setNotification("error", "No se encontró una cuenta asociada a este correo.");
            return false;
        }
    }

    public function sendVerification($email, $token) {
        $mail = new PHPMailer(true);
        try {
            //? Ajustes del servidor de correo
            $mail -> setLanguage('es');
            $mail -> isSMTP();
            $mail -> SMTPAuth = true;
            $mail -> Host = getenv('MAIL_HOST');
            $mail -> Username = getenv('MAIL_USERNAME');
            $mail -> Password = getenv('MAIL_PASSWORD'); // Recuerda generar un código de aplicación para esto
            $mail -> SMTPSecure = getenv('MAIL_ENCRYPTION');
            $mail -> Port = getenv('MAIL_PORT');

            //? Recipientes
            $mail -> setFrom(getenv('MAIL_FROM_ADDRESS'), getenv('MAIL_FROM_NAME')); // Emisor
            $mail -> addAddress($email); // Receptor

            //? Adjuntos
            // $mail -> addAttachment('/ruta/al/archivo.adjunto');

            //? Contenido
            $mail -> isHTML(true);
            $mail -> Subject = "Asunto del correo";
            $mail -> Body = "
            <style>
                a {
                    background-color: #105bc7;
                    padding: 5px;
                    width: fit-content;
                    border-radius: 8px;
                    text-decoration: none;
                    font-family: 'Arial', sans-serif, serif;
                    color: #fff;
                }
            </style>

            <h1>Activa tu cuenta</h1>
            <p>Este texto se debe modificar desde el .env</p>
            <div>
                <a href='". getenv('VERIFICATION_LINK') ."?token=$token'>Activar cuenta</a>
            </div>";
            
            $mail -> send();
            $this -> session -> setNotification("success", "Se envió un correo de verificación a la dirección que ingresaste, revisalo para activar tu cuenta.");

        } catch (Exception $e) {
            $this -> session -> setNotification("error", "No se pudo enviar el correo de verificación. Error: {$mail -> ErrorInfo}.");
        }
    }

    public function verifyAccount() {
        $token = $_GET['token'];

        //? Comprobar si el token coincide con el guardado en la DB
        $stmt = $this -> connection -> prepare("SELECT id, token_expiration FROM users WHERE token = ?");
        $stmt -> bind_param("s", $token);
        $stmt -> execute();
        $stmt -> store_result();

        if ($stmt -> num_rows > 0) {
            //? El token coincide
            $stmt -> bind_result($id, $tokenExpiration);
            $stmt -> fetch();
            $stmt -> close();

            $currentDate = date("Y-m-d H:i:s");

            if ($currentDate > $tokenExpiration) {
                //? El token ha expirado
                $this -> session -> setNotification("error", "El token de verificación ha expirado.");

            } else {
                //? Activar la cuenta y eliminar el token
                $stmt = $this -> connection -> prepare("UPDATE users SET token = NULL, status = 1, token_expiration = NULL WHERE id = ?");
                $stmt -> bind_param("i", $id);
    
                if ($stmt -> execute()) {
                    $this -> session -> setNotification("success", "Tu cuenta ha sido activada con éxito. Ahora debes iniciar sesión");
    
                } else {
                    $this -> session -> setNotification("error", "No se pudo activar la cuenta. Inténtalo de nuevo");
                }
                $stmt -> close();
            }
            
        } else {
            //? El token no coincide (Invalido o ya usado)
            $stmt -> close();
            $this -> session -> setNotification("error", "El token de verificación es inválido o ya ha sido utilizado");
        }
    }

    public function redirect($location) {
        header("Location: $location");
        exit();
    }

    //?  Función para verificar si la sesión está iniciada
    public function checkSession() {
        if ($this -> session -> isLoggedIn()) {
            return true;

        } else {
            $this -> session -> setNotification("error", "Debes iniciar sesión para acceder a esta página.");
            return false;
        }
    }
}