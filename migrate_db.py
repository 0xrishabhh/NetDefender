from app import app, db
from models import User

def migrate_database():
    with app.app_context():
        # Get the database connection
        conn = db.engine.connect()
        
        try:
            # Check existing columns
            result = conn.execute("PRAGMA table_info(user)")
            existing_columns = [row[1] for row in result]
            
            # Add new columns if they don't exist
            if 'phone_number' not in existing_columns:
                conn.execute("ALTER TABLE user ADD COLUMN phone_number VARCHAR(20)")
            
            if 'otp' not in existing_columns:
                conn.execute("ALTER TABLE user ADD COLUMN otp VARCHAR(6)")
            
            if 'otp_created_at' not in existing_columns:
                conn.execute("ALTER TABLE user ADD COLUMN otp_created_at DATETIME")
            
            if 'is_otp_verified' not in existing_columns:
                conn.execute("ALTER TABLE user ADD COLUMN is_otp_verified BOOLEAN DEFAULT FALSE")
                
            if 'otp_method' not in existing_columns:
                conn.execute("ALTER TABLE user ADD COLUMN otp_method VARCHAR(10)")

            if 'lockout_until' not in existing_columns:
                conn.execute("ALTER TABLE user ADD COLUMN lockout_until DATETIME")
            
            # Commit the transaction
            db.session.commit()
            print("Database migration completed successfully!")
            
        except Exception as e:
            print(f"Error during migration: {str(e)}")
            db.session.rollback()
        finally:
            conn.close()

if __name__ == "__main__":
    migrate_database() 