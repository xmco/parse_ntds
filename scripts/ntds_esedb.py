from impacket.ese import ESENT_DB
from dissect.esedb import EseDB
from logging_config import logger

class ESENTDB_Abstract(object):

    def __init__(self, ntds_path):
        self.path = ntds_path
        #self.tablename = tablename
        self.ese = ESENT_DB(ntds_path)
        self.tablename = ""

    def esentdb_open(self, tablename):

        self.tablename = tablename
        cursor = self.ese.openTable(tablename)
        if cursor is None:
            logger.error('Can"t get a cursor for table: %s' % tablename)
            return None

        logger.info("Openning table: %s" % tablename)
        
        return cursor

    def close(self):
        self.ese.close()

    def esentdb_readrow(self, cursor):

        record = None
        try:
            record = self.ese.getNextRow(cursor)
        except Exception:
            error_msg = "Error while calling getNextRow(), trying the next one"
            logger.debug('Exception:', exc_info=True)
            logger.error(error_msg)
        return record
    

class ESENTDB_AbstractDissect(object):

    def __init__(self, ntds_path):
        logger.info("ntds_path: "+ntds_path)
        self.ntds_file = open(ntds_path, "rb")
        self.path = ntds_path
        #self.tablename = tablename
        self.ese = EseDB(self.ntds_file)
        self.tablename = ""
        self.table = None

    def esentdb_open(self, tablename):

        self.tablename = tablename
        self.table = self.ese.table(tablename)
        if self.table is None:
            logger.error('Can"t get the table: %s' % tablename)
        logger.info("Opening table: %s" % tablename)
        

    def close(self):
        self.ntds_file.close()
        
    def esentdb_read_records(self):
        try:
            for record in self.table.records():
                yield record
        except Exception:
            error_msg = "Error while calling records()"
            logger.debug('Exception:', exc_info=True)
            logger.error(error_msg)
