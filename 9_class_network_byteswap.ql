import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    // TODO: replace <class> and <var>
exists(MacroInvocation m | m.getMacroName().regexpMatch("ntoh.*")     
    and 
    this=m.getExpr())
    
  } 
}

from NetworkByteSwap n
select n, "Network byte swap" 
