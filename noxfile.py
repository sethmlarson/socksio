import nox

nox.options.stop_on_first_error = True

source_files = ("socksio", "tests", "noxfile.py")


@nox.session()
def lint(session):
    session.install("autoflake", "black", "flake8", "isort", "seed-isort-config")

    session.run("autoflake", "--in-place", "--recursive", *source_files)
    session.run("seed-isort-config", "--application-directories=socksio")
    session.run("isort", "--project=socksio", "--recursive", "--apply", *source_files)
    session.run("black", "--target-version=py36", *source_files)

    check(session)


@nox.session(reuse_venv=True)
def check(session):
    session.install(
        "black", "flake8", "flake8-bugbear", "flake8-comprehensions", "mypy"
    )

    session.run("black", "--check", "--diff", "--target-version=py36", *source_files)
    session.run("flake8", *source_files)
    session.run("mypy", "--strict", "socksio")


@nox.session(python=["3.6", "3.7", "3.8"])
def test(session):
    session.install("-r", "test-requirements.txt")
    session.run("python", "-m", "pytest", *session.posargs)
