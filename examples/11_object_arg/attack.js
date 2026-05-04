// validateOrder бы кинул "price too high" — мы перехватываем и сбиваем цену.
// chargeCard потом видит модифицированный Order через тот же reference.
var App = Java.use('App');

App.validateOrder.implementation = function(orderOop) {
    var o = Java.cast(orderOop, 'Order');
    Marrow.log('intercepted: product=' + Java.toString(o.product) +
                 ' price=' + o.totalPrice + ' qty=' + o.quantity);

    o.totalPrice = 0.0;
    o.quantity = 1;
    // original validateOrder body MUTED — не throws. chargeCard теперь видит $0.
};
