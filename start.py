from midman.context import Context
from midman.manager import Manager
from midman.reporter import Reporter


if __name__ == "__main__":
    ctx = Context()

    reporter = Reporter(ctx)
    reporter.start()

    manager = Manager(ctx)
    manager.start()
