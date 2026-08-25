CREATE TABLE `devices` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`name` text NOT NULL,
	`identity_public_key` text NOT NULL,
	`identity_signature` text NOT NULL,
	`key_package` text NOT NULL,
	`key_package_signature` text NOT NULL,
	`key_package_version` text DEFAULT '1' NOT NULL,
	`active` text DEFAULT '1' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_devices_user_active` ON `devices` (`user_id`,`active`);--> statement-breakpoint
CREATE TABLE `mls_events` (
	`id` text PRIMARY KEY NOT NULL,
	`conversation_id` text NOT NULL,
	`sender_device_id` text NOT NULL,
	`kind` text NOT NULL,
	`payload` text NOT NULL,
	`epoch` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`conversation_id`) REFERENCES `conversations`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`sender_device_id`) REFERENCES `devices`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_mls_events_conversation_created` ON `mls_events` (`conversation_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `mls_welcomes` (
	`id` text PRIMARY KEY NOT NULL,
	`conversation_id` text NOT NULL,
	`recipient_user_id` text NOT NULL,
	`recipient_device_id` text NOT NULL,
	`recipient_key_package_version` text NOT NULL,
	`sender_device_id` text NOT NULL,
	`welcome` text NOT NULL,
	`ratchet_tree` text NOT NULL,
	`claimed_at` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`conversation_id`) REFERENCES `conversations`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`recipient_user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`recipient_device_id`) REFERENCES `devices`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`sender_device_id`) REFERENCES `devices`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_mls_welcomes_recipient_claimed` ON `mls_welcomes` (`recipient_device_id`,`claimed_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_mls_welcomes_key_package_once` ON `mls_welcomes` (`recipient_device_id`,`recipient_key_package_version`);--> statement-breakpoint
ALTER TABLE `messages` ADD `protocol` text DEFAULT 'legacy-aes-gcm' NOT NULL;--> statement-breakpoint
ALTER TABLE `messages` ADD `epoch` text;--> statement-breakpoint
ALTER TABLE `messages` ADD `sender_device_id` text REFERENCES devices(id);--> statement-breakpoint
ALTER TABLE `users` ADD `identity_public_key` text;