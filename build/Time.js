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

var Time = function () {
	//**********************************************************************************
	/**
  * Constructor for Time class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  * @property {number} [type] 0 - UTCTime; 1 - GeneralizedTime; 2 - empty value
  * @property {Date} [value] Value of the TIME class
  */

	function Time() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, Time);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description 0 - UTCTime; 1 - GeneralizedTime; 2 - empty value
   */
		this.type = (0, _pvutils.getParametersValue)(parameters, "type", Time.defaultValues("type"));
		/**
   * @type {Date}
   * @description Value of the TIME class
   */
		this.value = (0, _pvutils.getParametersValue)(parameters, "value", Time.defaultValues("value"));
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


	_createClass(Time, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, Time.schema({
				names: {
					utcTimeName: "utcTimeName",
					generalTimeName: "generalTimeName"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for TIME");
			//endregion

			//region Get internal properties from parsed schema
			if ("utcTimeName" in asn1.result) {
				this.type = 0;
				this.value = asn1.result.utcTimeName.toDate();
			}
			if ("generalTimeName" in asn1.result) {
				this.type = 1;
				this.value = asn1.result.generalTimeName.toDate();
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
			//region Construct and return new ASN.1 schema for this object
			var result = {};

			if (this.type === 0) result = new asn1js.UTCTime({ valueDate: this.value });
			if (this.type === 1) result = new asn1js.GeneralizedTime({ valueDate: this.value });

			return result;
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
			return {
				type: this.type,
				value: this.value
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "type":
					return 0;
				case "value":
					return new Date(0, 0, 0);
				default:
					throw new Error("Invalid member name for Time class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @param {boolean} optional Flag that current schema should be optional
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];
			var optional = arguments.length <= 1 || arguments[1] === undefined ? false : arguments[1];

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [utcTimeName] Name for "utcTimeName" choice
    * @property {string} [generalTimeName] Name for "generalTimeName" choice
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Choice({
				optional: optional,
				value: [new asn1js.UTCTime({ name: names.utcTimeName || "" }), new asn1js.GeneralizedTime({ name: names.generalTimeName || "" })]
			});
		}
	}]);

	return Time;
}();
//**************************************************************************************


exports.default = Time;
//# sourceMappingURL=Time.js.map