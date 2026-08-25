CREATE TABLE `device_key_packages` (
	`device_id` text NOT NULL,
	`version` text NOT NULL,
	`key_package` text NOT NULL,
	`key_package_signature` text NOT NULL,
	`consumed_at` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY(`device_id`, `version`),
	FOREIGN KEY (`device_id`) REFERENCES `devices`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_device_key_packages_available` ON `device_key_packages` (`device_id`,`consumed_at`);--> statement-breakpoint
CREATE TABLE `device_link_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`code_hash` text NOT NULL,
	`requester_name` text NOT NULL,
	`requester_public_key` text NOT NULL,
	`approver_public_key` text,
	`encrypted_transfer` text,
	`transfer_iv` text,
	`status` text DEFAULT 'pending' NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_device_link_sessions_code_hash` ON `device_link_sessions` (`code_hash`);--> statement-breakpoint
CREATE INDEX `idx_device_link_sessions_user_status` ON `device_link_sessions` (`user_id`,`status`);--> statement-breakpoint
CREATE TABLE `encrypted_backups` (
	`user_id` text PRIMARY KEY NOT NULL,
	`source_device_id` text,
	`ciphertext` text NOT NULL,
	`iv` text NOT NULL,
	`salt` text NOT NULL,
	`version` text DEFAULT '1' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`source_device_id`) REFERENCES `devices`(`id`) ON UPDATE no action ON DELETE set null
);
