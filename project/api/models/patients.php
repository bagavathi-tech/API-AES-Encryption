<?php
class Patient {

    // 🔹 GET ALL
    public static function all() {
        $db = Database::connect();
        $result = $db->query("SELECT * FROM patients");

        $patients = [];

        while ($row = $result->fetch_assoc()) {

            if (!empty($row['name'])) {
                $row['name'] = Crypto::decrypt($row['name']);
            }

            if (!empty($row['phone'])) {
                $row['phone'] = Crypto::decrypt($row['phone']);
            }

            if (!empty($row['address'])) {
                $row['address'] = Crypto::decrypt($row['address']);
            }

            $patients[] = $row;
        }

        return $patients;
    }

    // 🔹 GET BY ID
    public static function find($id) {
        $db = Database::connect();

        $stmt = $db->prepare("SELECT * FROM patients WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();

        $row = $stmt->get_result()->fetch_assoc();

        if ($row) {
            $row['name'] = Crypto::decrypt($row['name']);
            $row['phone'] = $row['phone'] ? Crypto::decrypt($row['phone']) : null;
            $row['address'] = $row['address'] ? Crypto::decrypt($row['address']) : null;
        }

        return $row;
    }

    // 🔹 CREATE
    public static function create($data) {
        $db = Database::connect();

        $nameRaw   = $data['name'];
        $age       = $data['age'];
        $gender    = $data['gender'];
        $phoneRaw  = $data['phone'] ?? null;
        $addressRaw = $data['address'] ?? null;

        $nameEncrypted    = Crypto::encrypt($nameRaw);
        $phoneEncrypted   = $phoneRaw ? Crypto::encrypt($phoneRaw) : null;
        $addressEncrypted = $addressRaw ? Crypto::encrypt($addressRaw) : null;

        $phoneHash = $phoneRaw ? Crypto::blindIndex($phoneRaw) : null;

        if ($phoneHash && self::findByPhoneHash($phoneHash)) {
            return false;
        }

        $stmt = $db->prepare(
            "INSERT INTO patients (name, age, gender, phone, phone_hash, address)
             VALUES (?, ?, ?, ?, ?, ?)"
        );

        $stmt->bind_param(
            "sissss",
            $nameEncrypted,
            $age,
            $gender,
            $phoneEncrypted,
            $phoneHash,
            $addressEncrypted
        );

        return $stmt->execute();
    }

    // 🔹 DUPLICATE CHECK
    public static function findByPhoneHash($hash) {
        $db = Database::connect();

        $stmt = $db->prepare(
            "SELECT id FROM patients WHERE phone_hash = ? LIMIT 1"
        );
        $stmt->bind_param("s", $hash);
        $stmt->execute();

        return $stmt->get_result()->fetch_assoc();
    }

    // 🔹 UPDATE
    public static function update($id, $data) {
        $db = Database::connect();

        $nameEncrypted    = Crypto::encrypt($data['name']);
        $age              = $data['age'];
        $gender           = $data['gender'];
        $phoneEncrypted   = $data['phone'] ? Crypto::encrypt($data['phone']) : null;
        $addressEncrypted = $data['address'] ? Crypto::encrypt($data['address']) : null;
        $phoneHash        = $data['phone'] ? Crypto::blindIndex($data['phone']) : null;

        $stmt = $db->prepare(
            "UPDATE patients
             SET name = ?, age = ?, gender = ?, phone = ?, phone_hash = ?, address = ?
             WHERE id = ?"
        );

        $stmt->bind_param(
            "sissssi",
            $nameEncrypted,
            $age,
            $gender,
            $phoneEncrypted,
            $phoneHash,
            $addressEncrypted,
            $id
        );

        return $stmt->execute();
    }

    // 🔹 DELETE
    public static function delete($id) {
        $db = Database::connect();

        $stmt = $db->prepare("DELETE FROM patients WHERE id = ?");
        $stmt->bind_param("i", $id);

        return $stmt->execute();
    }
}
