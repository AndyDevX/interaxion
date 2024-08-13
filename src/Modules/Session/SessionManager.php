<?php
namespace interaxion\Modules\Session;

class SessionManager {

    public function startSession() {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
    }

    public function set($key, $value) {
        $_SESSION[$key] = $value;
    }

    public function get($key) {
        return $_SESSION[$key] ?? null;
    }

    public function remove($key) {
        unset($_SESSION[$key]);
    }

    public function destroySession() {
        session_unset();
        session_destroy();
    }

    public function setNotification($type, $message) {
        $this->set("notification", [
            "type" => $type,
            "message" => $message
        ]);
    }

    public function getNotification() {
        $notification = $this->get("notification");
        $this -> remove("notification");
        return $notification;
    }

    public function isLoggedIn() {
        return $this -> get("islogged") === true;
    }
}