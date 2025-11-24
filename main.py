import em_reader as em
import calculator as c
import pybybit as pb

def main(identifier,price_a,price_b,symbol,type):
    
  if identifier == 1:  
    max_wait = int()
    key_dict = {
    "acc1": {
        "api_key": "OoRAfYzPq43Fgs3LM3",
        "api_secret": "5MOxtE17mWBK3KqZZSoesXIoq5os7C1WEHHP"
    }
}
    dict_a,dict_b = c.tcl_calc(price_a,price_b,symbol,type)
    pb.trade_tcl(key_dict,dict_a,dict_b, max_wait_seconds = 6000)


td_email = 'hellotagvg1@gmail.com'
em.start_spam_email_listener_recent(td_email,callback = main,poll_interval=3)

    
