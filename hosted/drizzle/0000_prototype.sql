CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,birthdate TEXT NOT NULL DEFAULT '',role TEXT NOT NULL DEFAULT 'member',active INTEGER NOT NULL DEFAULT 1,csrf TEXT NOT NULL);
--> statement-breakpoint
CREATE TABLE consultations(id TEXT PRIMARY KEY,profile_id TEXT NOT NULL REFERENCES users(id),title TEXT NOT NULL,created TEXT NOT NULL);
--> statement-breakpoint
CREATE TABLE messages(id TEXT PRIMARY KEY,consultation_id TEXT NOT NULL REFERENCES consultations(id),author_id TEXT NOT NULL,role TEXT NOT NULL,text TEXT NOT NULL,created TEXT NOT NULL);
--> statement-breakpoint
CREATE TABLE documents(id TEXT PRIMARY KEY,profile_id TEXT NOT NULL REFERENCES users(id),consultation_id TEXT NOT NULL REFERENCES consultations(id),name TEXT NOT NULL,mime TEXT NOT NULL,object_key TEXT NOT NULL,digest TEXT NOT NULL,extracted TEXT NOT NULL DEFAULT '',confirmed INTEGER NOT NULL DEFAULT 0,created TEXT NOT NULL,UNIQUE(profile_id,digest));
--> statement-breakpoint
CREATE TABLE document_revisions(id TEXT PRIMARY KEY,document_id TEXT NOT NULL REFERENCES documents(id),author_id TEXT NOT NULL,text TEXT NOT NULL,created TEXT NOT NULL);
--> statement-breakpoint
CREATE TABLE runs(id TEXT PRIMARY KEY,consultation_id TEXT NOT NULL REFERENCES consultations(id),status TEXT NOT NULL,result TEXT,error TEXT,created TEXT NOT NULL,expires INTEGER NOT NULL);
--> statement-breakpoint
CREATE TABLE audit(id INTEGER PRIMARY KEY,actor_id TEXT,profile_id TEXT,action TEXT,created TEXT);
