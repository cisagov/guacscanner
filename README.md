# guacscanner #

[![GitHub Build Status](https://github.com/cisagov/guacscanner/workflows/build/badge.svg)](https://github.com/cisagov/guacscanner/actions)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/guacscanner/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/guacscanner?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/guacscanner.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/guacscanner/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/guacscanner.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/guacscanner/context:python)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/guacscanner/develop/badge.svg)](https://snyk.io/test/github/cisagov/guacscanner)

This project is a Python utility that continually scans the instances
in an AWS VPC and adds/removes Guacamole connections in the underlying
PostgreSQL database accordingly.

This utility is [Dockerized](https://docker.com) in
[cisagov/guacscanner-docker](https://github.com/cisagov/guacscanner-docker),
and the resulting Docker container is intended to run as a part of
[cisagov/guacamole-composition](https://github.com/cisagov/guacamole-composition),
although it could - probably uselessly - run in a [Docker
composition](https://docs.docker.com/compose/) alongside only the
[official PostgreSQL Docker image](https://hub.docker.com/_/postgres).

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
