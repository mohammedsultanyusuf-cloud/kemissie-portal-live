CREATE DATABASE IF NOT EXISTS kemissie_school
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE kemissie_school;

CREATE TABLE IF NOT EXISTS students (
    student_id    VARCHAR(20)  NOT NULL PRIMARY KEY,
    name          VARCHAR(150) NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS grades (
    id         INT UNSIGNED     NOT NULL AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20)      NOT NULL,
    semester   TINYINT UNSIGNED NOT NULL,
    subject    VARCHAR(100)     NOT NULL,
    midterm    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    final_exam TINYINT UNSIGNED NOT NULL DEFAULT 0,
    UNIQUE KEY uq_student_sem_subject (student_id, semester, subject),
    CONSTRAINT fk_grades_student FOREIGN KEY (student_id)
        REFERENCES students (student_id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_semester CHECK (semester IN (1, 2)),
    CONSTRAINT chk_midterm  CHECK (midterm <= 40),
    CONSTRAINT chk_final    CHECK (final_exam <= 60)
) ENGINE=InnoDB;
