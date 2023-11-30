/*
  Warnings:

  - The primary key for the `UserGoogle` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to alter the column `id` on the `UserGoogle` table. The data in that column could be lost. The data in that column will be cast from `String` to `Int`.

*/
-- RedefineTables
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_UserGoogle" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL
);
INSERT INTO "new_UserGoogle" ("email", "id", "name") SELECT "email", "id", "name" FROM "UserGoogle";
DROP TABLE "UserGoogle";
ALTER TABLE "new_UserGoogle" RENAME TO "UserGoogle";
CREATE UNIQUE INDEX "UserGoogle_email_key" ON "UserGoogle"("email");
PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;
