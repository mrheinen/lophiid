package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/kkyr/fig"
	"lophiid/pkg/backend"
)

func main() {
	partitionsOnly := flag.Bool("partitions-only", false, "Only manage partitions (skip schema and user setup)")
	dbUser := flag.String("db-user", "postgres", "Database superuser username")
	dbPassword := flag.String("db-password", "postgres", "Database superuser password")
	dbHost := flag.String("db-host", "localhost", "Database host")
	appUser := flag.String("app-user", "lo", "Application username to create/update")
	appPassword := flag.String("app-password", "lo", "Application user password")
	schemaPath := flag.String("schema-path", "./config/database.sql", "Path to the database schema SQL file")
	configPath := flag.String("config", "backend-config.yaml", "Path to the backend configuration file")
	
	// Override for the target DB name if we want to create something other than what's in config
	targetDBName := flag.String("db-name", "", "Target database name (overrides config)")

	flag.Parse()

	var cfg backend.Config
	var opts []fig.Option

	if *configPath != "" {
		// If a specific config file is provided, try to load it
		dir := filepath.Dir(*configPath)
		file := filepath.Base(*configPath)
		opts = append(opts, fig.Dirs(dir), fig.File(file))
	} else {
		// Otherwise, look in current directory or standard locations, but don't fail if missing
		opts = append(opts, fig.IgnoreFile()) 
	}

	err := fig.Load(&cfg, opts...)
	if err != nil {
		// If specific config was requested but failed, that's worth logging or fatal-ing depending on strictness.
		// But since we have fallbacks, just log.
		log.Printf("Note: Could not load backend config file: %v. Using defaults and flags.", err)
	}
	
	// Determine Target Database Name
	// Priority: Flag -> Env -> Config URL parsing -> Default "lophiid"
	dbName := "lophiid" // Default
	
	if *targetDBName != "" {
		dbName = *targetDBName
	} else if v := os.Getenv("DB_NAME"); v != "" {
		dbName = v
	}
	
	// Determine Host/Port
	host := *dbHost

	if v := os.Getenv("DB_HOST"); v != "" { host = v }
	
	port := 5432
	if v := os.Getenv("DB_PORT"); v != "" { fmt.Sscanf(v, "%d", &port) }

	// Create context globally for use in all steps
	ctx := context.Background()

	// 0. Create Database if needed
	// Connect to 'postgres' database to perform admin actions
	maintenanceDSN := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
		host, port, *dbUser, *dbPassword)
	
	adminDB, err := sql.Open("pgx", maintenanceDSN)
	if err != nil {
		log.Fatalf("Error connecting to maintenance DB: %v", err)
	}
	
	// Short timeout for ping
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := adminDB.PingContext(pingCtx); err != nil {
		log.Fatalf("Error pinging maintenance DB: %v", err)
	}
	cancel()
	
	if !*partitionsOnly {
		fmt.Printf("Checking if database '%s' exists...\n", dbName)
		var exists bool
		err = adminDB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbName).Scan(&exists)
		if err != nil {
			log.Fatalf("Error checking database existence: %v", err)
		}
		
		if !exists {
			fmt.Printf("Database '%s' does not exist. Creating...\n", dbName)
			// CREATE DATABASE cannot run in a transaction block
			_, err = adminDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE \"%s\"", dbName))
			if err != nil {
				log.Fatalf("Error creating database: %v", err)
			}
			fmt.Println("Database created successfully.")
		} else {
			fmt.Printf("Database '%s' already exists.\n", dbName)
		}
	}
	adminDB.Close()

	// 1. Connect to Target Database
	targetDSN := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, *dbUser, *dbPassword, dbName)

	db, err := sql.Open("pgx", targetDSN)
	if err != nil {
		log.Fatalf("Error connecting to target database: %v", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("Error pinging target database: %v", err)
	}

	fmt.Printf("Connected to target database '%s'!\n", dbName)

	if !*partitionsOnly {
		// 2. Run Schema
		// Check if schema file exists
		schemaContent, err := ioutil.ReadFile(*schemaPath)
		if err != nil {
			log.Printf("Warning: Could not read schema file at %s: %v. Assuming schema already exists or skipping initial load.", *schemaPath, err)
		} else {
			fmt.Println("Applying schema...")
			
			// Clean schema content of psql meta-commands
			lines := strings.Split(string(schemaContent), "\n")
			var cleanLines []string
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "\\") {
					continue
				}
				cleanLines = append(cleanLines, line)
			}
			cleanSchema := strings.Join(cleanLines, "\n")

			_, err = db.ExecContext(ctx, cleanSchema)
			if err != nil {
				log.Printf("Error applying schema: %v. Continuing, assuming it might be partial duplicate errors.", err)
			} else {
				fmt.Println("Schema applied successfully.")
			}
		}

		// 3. Create User and Grants
		fmt.Println("Configuring application user...")
		err = createOrUpdateUser(ctx, db, *appUser, *appPassword)
		if err != nil {
			log.Fatalf("Error configuring user: %v", err)
		}

		err = grantPermissions(ctx, db, *appUser)
		if err != nil {
			log.Fatalf("Error granting permissions: %v", err)
		}
	} else {
		fmt.Println("Skipping database creation, schema, and user setup (partitions-only mode).")
	}

	// 4. Create Partitions
	fmt.Println("Managing partitions...")
	err = managePartitions(ctx, db)
	if err != nil {
		log.Fatalf("Error managing partitions: %v", err)
	}

	fmt.Println("Setup complete!")
}

func createOrUpdateUser(ctx context.Context, db *sql.DB, username, password string) error {
	// Check if user exists
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", username).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		fmt.Printf("User %s exists, updating password...\n", username)
		_, err = db.ExecContext(ctx, fmt.Sprintf("ALTER USER %s WITH PASSWORD '%s'", username, password))
	} else {
		fmt.Printf("Creating user %s...\n", username)
		_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE USER %s WITH PASSWORD '%s'", username, password))
	}
	return err
}

func grantPermissions(ctx context.Context, db *sql.DB, username string) error {
	// Grant usage and create on schema public
	_, err := db.ExecContext(ctx, fmt.Sprintf("GRANT USAGE, CREATE ON SCHEMA public TO %s", username))
	if err != nil {
		return err
	}

	// Grant all privileges on all tables in schema public
	_, err = db.ExecContext(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO %s", username))
	if err != nil {
		return err
	}

	// Grant all privileges on all sequences in schema public
	_, err = db.ExecContext(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO %s", username))
	if err != nil {
		return err
	}

	// Grant all privileges on all functions in schema public
	_, err = db.ExecContext(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO %s", username))
	if err != nil {
		return err
	}
	
	// Ensure future tables get these privileges too
	_, err = db.ExecContext(ctx, fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO %s", username))
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO %s", username))
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO %s", username))
	
	return err
}

func managePartitions(ctx context.Context, db *sql.DB) error {
	now := time.Now().UTC()
	
	currentYear := now.Year()
	currentMonth := int(now.Month())
	
	endYear := currentYear + 1
	
	iterYear := currentYear
	iterMonth := currentMonth
	
	// Normalize iterMonth to start of a 2-month block
	if iterMonth % 2 == 0 {
		iterMonth -= 1
	}
	
	for {
		if iterYear > endYear {
			break
		}
		
		// Construct start and end dates for the partition
		// Start: 1st of iterMonth
		// End: 1st of (iterMonth + 2)
		
		start := time.Date(iterYear, time.Month(iterMonth), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 2, 0)
		
		// Table name format: request_yYYYYmMM_MM
		m1 := iterMonth
		m2 := iterMonth + 1
		tableName := fmt.Sprintf("request_y%04dm%02d_%02d", iterYear, m1, m2)
		
		// Range values
		startStr := start.Format("2006-01-02 00:00:00")
		endStr := end.Format("2006-01-02 00:00:00")
		
		fmt.Printf("Ensuring partition %s (%s to %s)...\n", tableName, startStr, endStr)
		
		query := fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS public.%s PARTITION OF public.request
			FOR VALUES FROM ('%s') TO ('%s');
		`, tableName, startStr, endStr)
		
		_, err := db.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create partition %s: %w", tableName, err)
		}
		
		// Move to next block
		iterMonth += 2
		if iterMonth > 12 {
			iterMonth = 1
			iterYear += 1
		}
	}
	
	return nil
}
