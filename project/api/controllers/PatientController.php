<?php
class PatientController {

    // 🔹 GET /api/patients
    public static function index() {
        AuthMiddleware::handle();

        $patients = Patient::all();
        Response::json(200, "Patients", $patients);
    }

    // 🔹 GET /api/patients/{id}
    public static function show($id) {
        AuthMiddleware::handle();

        $patient = Patient::find($id);

        if (!$patient) {
            Response::json(404, "Patient not found");
        }

        Response::json(200, "Patient", $patient);
    }

    // 🔹 POST /api/patients
    public static function store($data) {
        AuthMiddleware::handle();

        if (
            empty($data['name']) ||
            empty($data['age']) ||
            empty($data['gender'])
        ) {
            Response::json(400, "Name, age and gender required");
        }

        $created = Patient::create($data);

        if (!$created) {
            Response::json(409, "Phone already exists");
        }

        Response::json(201, "Patient created successfully");
    }

    // 🔹 PUT /api/patients/{id}
    public static function update($id, $data) {
        AuthMiddleware::handle();

        if (
            empty($data['name']) ||
            empty($data['age']) ||
            empty($data['gender'])
        ) {
            Response::json(400, "PUT requires all fields");
        }

        Patient::update($id, $data);

        Response::json(200, "Patient updated successfully");
    }

    // 🔹 DELETE /api/patients/{id}
    public static function delete($id) {
        AuthMiddleware::handle();

        Patient::delete($id);

        Response::json(200, "Patient deleted successfully");
    }
}
