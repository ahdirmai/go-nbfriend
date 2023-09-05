package config

import (
	"database/sql"
	"fmt"
)

func ConnectDB() (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		"containers-us-west-72.railway.app",
		"6027",
		"postgres",
		"Avk07cmtqI8BzPmR4zOp",
		"railway",
	)

	db, err := sql.Open("postgres", dsn)

	if err != nil {
		return nil, err // Mengembalikan error jika terjadi kesalahan
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil // Mengembalikan koneksi DB jika berhasil
}
