# Light client DNS seeder

Compact block filter clients require peers that signal for compact filter support. This binary crawls the Bitcoin peer-to-peer network and searches for such peers. Occasionally, peers are polled for their response speed when syncing compact block filters, and faster peers have a higher probability of being served. For other DNS seeders, one may fork this project and replace the `poller` with different logic.

`deploy.md` contains steps to run this seeder on a VPS.
