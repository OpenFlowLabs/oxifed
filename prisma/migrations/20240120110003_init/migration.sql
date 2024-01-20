-- CreateExtension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- CreateEnum
CREATE TYPE "KeyType" AS ENUM ('Ed25519');

-- CreateTable
CREATE TABLE "Domain" (
    "id" UUID NOT NULL,
    "dnsName" TEXT NOT NULL,
    "applications" TEXT[],

    CONSTRAINT "Domain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Actor" (
    "id" UUID NOT NULL,
    "displayName" TEXT NOT NULL,
    "handle" TEXT NOT NULL,
    "domainId" UUID NOT NULL,

    CONSTRAINT "Actor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Key" (
    "id" UUID NOT NULL,
    "actorId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "private_key" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "key_type" "KeyType" NOT NULL DEFAULT 'Ed25519',

    CONSTRAINT "Key_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Article" (
    "id" UUID NOT NULL,
    "descriptor" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "date" TIMESTAMP(3) NOT NULL,
    "content" TEXT NOT NULL,
    "content_html" TEXT NOT NULL,
    "draft" BOOLEAN NOT NULL DEFAULT false,
    "tags" TEXT[],
    "noteId" UUID NOT NULL,
    "publishedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Article_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Note" (
    "id" UUID NOT NULL,
    "descriptor" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "bodyHtml" TEXT NOT NULL,
    "authorId" UUID NOT NULL,
    "parentId" UUID,
    "postedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Note_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Domain_dnsName_key" ON "Domain"("dnsName");

-- CreateIndex
CREATE UNIQUE INDEX "Actor_handle_key" ON "Actor"("handle");

-- CreateIndex
CREATE UNIQUE INDEX "Article_descriptor_key" ON "Article"("descriptor");

-- CreateIndex
CREATE UNIQUE INDEX "Article_noteId_key" ON "Article"("noteId");

-- CreateIndex
CREATE UNIQUE INDEX "Note_descriptor_key" ON "Note"("descriptor");

-- AddForeignKey
ALTER TABLE "Actor" ADD CONSTRAINT "Actor_domainId_fkey" FOREIGN KEY ("domainId") REFERENCES "Domain"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Key" ADD CONSTRAINT "Key_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "Actor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Article" ADD CONSTRAINT "Article_noteId_fkey" FOREIGN KEY ("noteId") REFERENCES "Note"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Note" ADD CONSTRAINT "Note_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "Actor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Note" ADD CONSTRAINT "Note_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "Note"("id") ON DELETE NO ACTION ON UPDATE NO ACTION;
