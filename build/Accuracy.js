"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************
/**
 * Class from RFC3161
 */

var Accuracy = function () {
	//**********************************************************************************
	/**
  * Constructor for Accuracy class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function Accuracy() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, Accuracy);

		//region Internal properties of the object
		if ("seconds" in parameters)
			/**
    * @type {number}
    * @description seconds
    */
			this.seconds = (0, _pvutils.getParametersValue)(parameters, "seconds", Accuracy.defaultValues("seconds"));

		if ("millis" in parameters)
			/**
    * @type {number}
    * @description millis
    */
			this.millis = (0, _pvutils.getParametersValue)(parameters, "millis", Accuracy.defaultValues("millis"));

		if ("micros" in parameters)
			/**
    * @type {number}
    * @description micros
    */
			this.micros = (0, _pvutils.getParametersValue)(parameters, "micros", Accuracy.defaultValues("micros"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(Accuracy, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, Accuracy.schema({
				names: {
					seconds: "seconds",
					millis: "millis",
					micros: "micros"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for tsp.Accuracy");
			//endregion

			//region Get internal properties from parsed schema
			if ("seconds" in asn1.result) this.seconds = asn1.result.seconds.valueBlock.valueDec;

			if ("millis" in asn1.result) {
				var intMillis = new asn1js.Integer({ valueHex: asn1.result.millis.valueBlock.valueHex });
				this.millis = intMillis.valueBlock.valueDec;
			}

			if ("micros" in asn1.result) {
				var intMicros = new asn1js.Integer({ valueHex: asn1.result.micros.valueBlock.valueHex });
				this.micros = intMicros.valueBlock.valueDec;
			}
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array of output sequence
			var outputArray = [];

			if ("seconds" in this) outputArray.push(new asn1js.Integer({ value: this.seconds }));

			if ("millis" in this) {
				var intMillis = new asn1js.Integer({ value: this.millis });

				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					valueHex: intMillis.valueBlock.valueHex
				}));
			}

			if ("micros" in this) {
				var intMicros = new asn1js.Integer({ value: this.micros });

				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					valueHex: intMicros.valueBlock.valueHex
				}));
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var _object = {};

			if ("seconds" in this) _object.seconds = this.seconds;

			if ("millis" in this) _object.millis = this.millis;

			if ("micros" in this) _object.micros = this.micros;

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "seconds":
				case "millis":
				case "micros":
					return 0;
				default:
					throw new Error("Invalid member name for Accuracy class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "seconds":
				case "millis":
				case "micros":
					return memberValue === Accuracy.defaultValues(memberName);
				default:
					throw new Error("Invalid member name for Accuracy class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//Accuracy ::= SEQUENCE {
			//    seconds        INTEGER              OPTIONAL,
			//    millis     [0] INTEGER  (1..999)    OPTIONAL,
			//    micros     [1] INTEGER  (1..999)    OPTIONAL  }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [seconds]
    * @property {string} [millis]
    * @property {string} [micros]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				optional: true,
				value: [new asn1js.Integer({
					optional: true,
					name: names.seconds || ""
				}), new asn1js.Primitive({
					name: names.millis || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}), new asn1js.Primitive({
					name: names.micros || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				})]
			});
		}
	}]);

	return Accuracy;
}();
//**************************************************************************************


exports.default = Accuracy;
//# sourceMappingURL=Accuracy.js.map