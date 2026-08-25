CREATE TABLE `attachments` (
	`id` text PRIMARY KEY NOT NULL,
	`conversation_id` text NOT NULL,
	`owner_id` text NOT NULL,
	`kind` text NOT NULL,
	`plaintext_size` text NOT NULL,
	`ciphertext_size` text NOT NULL,
	`thumbnail_ciphertext_size` text,
	`object_key` text NOT NULL,
	`thumbnail_object_key` text,
	`retention` text DEFAULT '7d' NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`expires_at` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`deleted_at` text,
	FOREIGN KEY (`conversation_id`) REFERENCES `conversations`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`owner_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_attachments_object_key` ON `attachments` (`object_key`);--> statement-breakpoint
CREATE INDEX `idx_attachments_conversation_status` ON `attachments` (`conversation_id`,`status`);--> statement-breakpoint
CREATE INDEX `idx_attachments_expiry_status` ON `attachments` (`expires_at`,`status`);