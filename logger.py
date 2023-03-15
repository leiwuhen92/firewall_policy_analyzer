import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s',
    # filename='analyze.log',
    # filemode='a'
)

logger = logging.getLogger()  # 查看logger
