import logging

# Set up logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def configure_logger(verbosity='ERROR'):
    # Override logger level based on verbosity argument
    verbosity_level = getattr(logging, verbosity.upper(), logging.INFO)
    logger.setLevel(verbosity_level)
    logger.debug(f"Logger configured to {verbosity} level")
