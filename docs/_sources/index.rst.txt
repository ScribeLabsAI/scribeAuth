.. Scribe Auth documentation master file, created by
   sphinx-quickstart on Mon Aug 15 11:26:51 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Scribe Auth's documentation
=======================================

Most calls to Scribe's API require authentication and authorization. This library simplifies this process.

You first need a Scribe account and a client ID. Both can be requested at support[atsign]scribelabs[dotsign]ai or through Intercom on https://platform.scribelabs.ai if you already have a Scribe account.

This library interacts directly with our authentication provider AWS Cognito meaning that your username and password never transit through our servers.

.. toctree::
   :maxdepth: 3
   :caption: Contents:


* :ref:`search`

Table of contents
=================

.. toctree::

   installation
   methods
   reference
   flow
   commandline
   