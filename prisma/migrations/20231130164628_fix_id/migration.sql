/*
  Warnings:

  - The primary key for the `User` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `UserGoogle` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- RedefineTables
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT false
);
INSERT INTO "new_User" ("email", "id", "isActive", "name", "password") SELECT "email", "id", "isActive", "name", "password" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_id_key" ON "User"("id");
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE TABLE "new_UserGoogle" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL
);
INSERT INTO "new_UserGoogle" ("email", "id", "name") SELECT "email", "id", "name" FROM "UserGoogle";
DROP TABLE "UserGoogle";
ALTER TABLE "new_UserGoogle" RENAME TO "UserGoogle";
CREATE UNIQUE INDEX "UserGoogle_id_key" ON "UserGoogle"("id");
CREATE UNIQUE INDEX "UserGoogle_email_key" ON "UserGoogle"("email");
PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;
