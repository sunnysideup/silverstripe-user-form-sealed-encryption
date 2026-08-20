<?php

declare(strict_types=1);

namespace Sunnysideup\UserFormSealedEncryption\Tasks;

use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;
use SilverStripe\PolyExecution\PolyOutput;
use Sunnysideup\UserFormSealedEncryption\Api\SealedBox;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;

/**
 * GenerateSealedBoxKeysTask
 * =========================================================================
 * Generates a fresh libsodium sealed-box keypair for the encryption module.
 *
 * SAFETY MODEL
 * ------------
 * This task is locked down two independent ways:
 *
 *   1. CLI ONLY   — $can_run_in_browser = false stops it being reachable
 *                   over HTTP at all. An explicit Director::is_cli() guard
 *                   inside execute() backs that up.
 *
 *   2. DEV ONLY   — execute() aborts unless the site is in dev mode, so it
 *                   can never run on a live/staging environment even from
 *                   the command line.
 *
 * WHY PRINT TO THE TERMINAL (and not write a file)?
 * -------------------------------------------------
 * The whole point of the sealed box is that the SECRET key must never touch
 * the server. Writing it to disk here would defeat that. Instead the keys
 * are printed to stdout so you can copy them straight off your terminal:
 *   - put the PUBLIC key into the server's environment/config;
 *   - move the SECRET key somewhere the server can never reach, and delete
 *     your shell history / scrollback afterwards.
 *
 * HOW TO RUN (Silverstripe 6 sake syntax)
 * ---------------------------------------
 *   vendor/bin/sake tasks:generate-sealed-box-keys
 *
 * (Legacy `sake dev/tasks/...` still works but is deprecated in v6.)
 */
final class GenerateSealedBoxKeysTask extends BuildTask
{
    /**
     * The command name — used for both the CLI command and the dev route.
     * Tasks may NOT contain a namespace in the command name (v6 rule).
     */
    protected static string $commandName = 'generate-sealed-box-keys';

    /** Printed by BuildTask::run() before execute() is called. */
    protected string $title = 'Generate Sealed Box encryption keys';

    protected static string $description =
        'Generate a libsodium sealed-box keypair (public + secret). '
        . 'CLI + dev mode only. Never writes the secret to disk.';

    /**
     * Block all browser/HTTP access. The task is CLI-only.
     * This is a config property read by the framework before dispatch.
     */
    private static bool $can_run_in_browser = false;

    /**
     * The actual work.
     */
    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        // --- Guard 1: command line only (defence in depth) -------------
        if (!Director::is_cli()) {
            $output->writeln('<error>This task can only be run from the command line.</error>');
            return Command::FAILURE;
        }

        // --- Guard 2: dev mode only ------------------------------------
        if (!Director::isDev()) {
            $output->writeln('<error>This task can only be run in dev mode.</error>');
            $output->writeln(
                '<comment>Set the environment to dev (e.g. SS_ENVIRONMENT_TYPE="dev" '
                . 'in your .env) and try again.</comment>'
            );
            return Command::FAILURE;
        }

        // --- Generate the keypair --------------------------------------
        try {
            $keys = SealedBox::generate_keypair();
        } catch (\Throwable $e) {
            $output->writeln('<error>Key generation failed: ' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        }

        // --- Output -----------------------------------------------------
        $output->writeln('');
        $output->writeln('<info>Keypair generated successfully.</info>');
        $output->writeln('');

        $output->writeln('<comment>PUBLIC KEY (Key A) — goes ON the server:</comment>');
        $output->writeln($keys['public']);
        $output->writeln('');

        $output->writeln('<comment>SECRET KEY (Key B) — keep OFF the server:</comment>');
        $output->writeln($keys['secret']);
        $output->writeln('');

        $output->writeln('<comment>Next steps:</comment>');
        $output->writeln(' 1. Add the PUBLIC key to your environment, e.g. in .env:');
        $output->writeln('       SS_SEALED_BOX_PUBLIC_KEY="' . $keys['public'] . '"');
        $output->writeln(' 2. Move the SECRET key to a safe place the server cannot reach');
        $output->writeln('    (offline vault, password manager, hardware token).');
        $output->writeln(' 3. NEVER commit the secret key. NEVER store it on this server.');
        $output->writeln(' 4. Clear your shell scrollback/history so the secret is not left behind.');
        $output->writeln('');
        $output->writeln(
            '<comment>Reminder: if you lose the secret key the data is unrecoverable — '
            . 'that is by design.</comment>'
        );
        $output->writeln('');

        return Command::SUCCESS;
    }
}
