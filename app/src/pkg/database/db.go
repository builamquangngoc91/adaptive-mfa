package database

import (
	"adaptive-mfa/pkg/logger"
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"time"
)

//go:generate mockgen -source=db.go -destination=./mock/db.go -package=mock
type IDatabase interface {
	GetDB() *sql.DB
	Ping(ctx context.Context) error
	Close() error
	StartTx(ctx context.Context, fn TxFunc, opts *sql.TxOptions) error
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row
	Prepare(ctx context.Context, query string) (*sql.Stmt, error)
	ExecTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (sql.Result, error)
	QueryTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) *sql.Row
	PrepareTx(ctx context.Context, tx *sql.Tx, query string) (*sql.Stmt, error)
}

type DatabaseConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	DBName          string
	Schema          string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type Database struct {
	db *sql.DB
}

func NewDatabase(cfg *DatabaseConfig) (IDatabase, error) {
	db, err := sql.Open("postgres", makeDSN(cfg))
	if err != nil {
		return nil, err
	}

	// Setup connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	return &Database{db: db}, nil
}

func makeDSN(cfg *DatabaseConfig) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)
}

func (d *Database) GetDB() *sql.DB {
	return d.db
}

type TxFunc func(ctx context.Context, tx *sql.Tx) error

func (d *Database) StartTx(ctx context.Context, fn TxFunc, opts *sql.TxOptions) error {
	tx, err := d.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	logger.NewLogger().
		WithContext(ctx).
		With("tx", tx).
		Info("Starting transaction")

	if err := fn(ctx, tx); err != nil {
		logger.NewLogger().
			WithContext(ctx).
			With("tx", tx).
			With("error", err).
			Error("Rolling back transaction")
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	logger.NewLogger().
		WithContext(ctx).
		With("tx", tx).
		Info("Committing transaction")
	return tx.Commit()
}

func (d *Database) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	result, err := d.db.ExecContext(ctx, query, args...)
	if err != nil {
		d.logQuery(ctx, query, err, args...)
		return nil, err
	}
	d.logQuery(ctx, query, nil, args...)
	return result, nil
}

func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		d.logQuery(ctx, query, err, args...)
		return nil, err
	}
	d.logQuery(ctx, query, nil, args...)
	return rows, nil
}

func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	d.logQuery(ctx, query, nil, args...)
	return d.db.QueryRowContext(ctx, query, args...)
}

func (d *Database) Prepare(ctx context.Context, query string) (*sql.Stmt, error) {
	return d.db.PrepareContext(ctx, query)
}

func (d *Database) ExecTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (sql.Result, error) {
	if tx == nil {
		return d.Exec(ctx, query, args...)
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		d.logQuery(ctx, query, err, args...)
		return nil, err
	}
	d.logQuery(ctx, query, nil, args...)
	return result, nil
}

func (d *Database) QueryTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (*sql.Rows, error) {
	if tx == nil {
		return d.Query(ctx, query, args...)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		d.logQuery(ctx, query, err, args...)
		return nil, err
	}
	d.logQuery(ctx, query, nil, args...)
	return rows, nil
}

func (d *Database) QueryRowTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) *sql.Row {
	if tx == nil {
		return d.QueryRow(ctx, query, args...)
	}
	d.logQuery(ctx, query, nil, args...)
	return tx.QueryRowContext(ctx, query, args...)
}

func (d *Database) PrepareTx(ctx context.Context, tx *sql.Tx, query string) (*sql.Stmt, error) {
	if tx == nil {
		return d.Prepare(ctx, query)
	}
	return tx.PrepareContext(ctx, query)
}

func (d *Database) logQuery(ctx context.Context, query string, err error, args ...interface{}) {
	logger.NewLogger().
		WithContext(ctx).
		With("query", query).
		With("args", args).
		With("error", err).
		With("query_parsed", d.parseSQL(query, args...)).
		Info("Executing query")
}

func (d *Database) parseSQL(query string, args ...interface{}) string {
	for i, arg := range args {
		if reflect.TypeOf(arg).Kind() == reflect.Pointer {
			if reflect.ValueOf(arg).IsNil() {
				arg = nil
			} else {
				arg = reflect.ValueOf(arg).Elem().Interface()
			}
		}

		statementSymbol := fmt.Sprintf("$%d", i+1)

		if arg == nil {
			query = strings.ReplaceAll(query, statementSymbol, "NULL")
			continue
		}

		switch v := arg.(type) {
		case string:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("'%s'", v))
		case int, int8, int16, int32, int64:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v))
		case float64:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%f", v))
		case time.Time:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("'%s'", v.Format("2006-01-02 15:04:05")))
		case bool:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%t", v))
		case []byte:
			query = strings.ReplaceAll(query, statementSymbol, string(v))
		case byte:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v))
		case sql.NullString:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("'%s'", v.String))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		case sql.NullInt16:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v.Int16))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		case sql.NullInt64:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v.Int64))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		case sql.NullInt32:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v.Int32))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		case sql.NullFloat64:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%f", v.Float64))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		case sql.NullBool:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%t", v.Bool))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		case sql.NullByte:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v.Byte))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		case sql.NullTime:
			if v.Valid {
				query = strings.ReplaceAll(query, statementSymbol, v.Time.Format("2006-01-02 15:04:05"))
			} else {
				query = strings.ReplaceAll(query, statementSymbol, "NULL")
			}
		default:
			query = strings.ReplaceAll(query, statementSymbol, "NULL")
		}
	}
	return query
}
