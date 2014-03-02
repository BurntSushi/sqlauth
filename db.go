package sqlauth

import (
	"database/sql"

	"code.google.com/p/go.crypto/bcrypt"

	"github.com/BurntSushi/csql"
	"github.com/BurntSushi/locker"
)

var (
	SqlTableName      = "auth_password"
	SqlCreatePassword = `
	CREATE TABLE IF NOT EXISTS ` + SqlTableName + ` (
		id TEXT NOT NULL,
		hash BYTEA NOT NULL,
		PRIMARY KEY (id, hash)
	)
	`
)

type Store struct {
	*sql.DB
}

func Open(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(SqlCreatePassword); err != nil {
		return nil, err
	}

	s := &Store{
		DB: db,
	}
	return s, nil
}

// Authenticate returns true if and only if the plain text password given
// matches the password hash associated with the user. An error is returned
// if there was a problem finding the user given or if there was an unexpected
// error comparing the password hashes. If the password does not match, then
// the error is nil and the bool is false.
func (s *Store) Authenticate(id, password string) (bool, error) {
	hash, err := s.Get(id)
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err == nil {
		return true, nil
	} else if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	} else {
		return false, err
	}
}

// Get retrieves the current password hash for the user given.
func (s *Store) Get(id string) (hash []byte, err error) {
	csql.Safe(&err)

	r := s.QueryRow(`
		SELECT hash FROM `+SqlTableName+` WHERE id = $1
		`, id)
	csql.Scan(r, &hash)
	return
}

// Set associates the plain text password given with the user that is uniquely
// identified by id. The password is hashed with bcrypt. If there is a problem
// with hashing or with storing the password, an error is returned.
//
// This may be called on a new user.
func (s *Store) Set(id, password string) (cerr error) {
	defer csql.Safe(&cerr)

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// This lock can be avoided if we use some sort of upsert.
	// It's possible with Postgres, but this is just way easier.
	locker.Lock(id)
	defer locker.Unlock(id)

	n := csql.Count(s, `
		SELECT COUNT(*) FROM `+SqlTableName+` WHERE id = $1
		`, id)
	if n == 0 {
		csql.Exec(s, `
			INSERT INTO `+SqlTableName+` (id, hash) VALUES ($1, $2)
			`, id, hash)
	} else {
		csql.Exec(s, `
			UPDATE `+SqlTableName+` SET id = $1, hash = $2 WHERE id = $1
			`, id, hash)
	}
	return nil
}
