CREATE TABLE `abuse_restrictions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`scope` text NOT NULL,
	`reason` text NOT NULL,
	`created_by` text NOT NULL,
	`expires_at` text,
	`revoked_at` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_abuse_restrictions_user_active` ON `abuse_restrictions` (`user_id`,`revoked_at`,`expires_at`);--> statement-breakpoint
CREATE TABLE `rate_limit_buckets` (
	`actor_key` text NOT NULL,
	`scope` text NOT NULL,
	`window_start` integer NOT NULL,
	`request_count` integer DEFAULT 0 NOT NULL,
	`cost` integer DEFAULT 0 NOT NULL,
	`expires_at` integer NOT NULL,
	PRIMARY KEY(`actor_key`, `scope`, `window_start`)
);
--> statement-breakpoint
CREATE INDEX `idx_rate_limit_buckets_expiry` ON `rate_limit_buckets` (`expires_at`);--> statement-breakpoint
CREATE TABLE `security_events` (
	`id` text PRIMARY KEY NOT NULL,
	`actor_id` text,
	`category` text NOT NULL,
	`severity` text NOT NULL,
	`endpoint` text NOT NULL,
	`metadata` text DEFAULT '{}' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`actor_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `idx_security_events_created_at` ON `security_events` (`created_at`);--> statement-breakpoint
CREATE INDEX `idx_security_events_category_created` ON `security_events` (`category`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_security_events_actor_created` ON `security_events` (`actor_id`,`created_at`);