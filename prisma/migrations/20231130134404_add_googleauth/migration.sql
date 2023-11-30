-- CreateTable
CREATE TABLE "UserGoogle" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "UserGoogle_email_key" ON "UserGoogle"("email");
